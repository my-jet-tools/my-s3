//! A minimal S3-compatible server that runs in the test process.
//!
//! The point is to drive the real client through a real socket, so the things that only
//! exist on the wire get checked: the SigV4 signature, the exact request target, the
//! framing headers, and the status codes. It deliberately re-derives the signature with
//! its own code rather than calling into `my_s3` - a test that shares the
//! implementation would agree with any bug in it.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

type HmacSha256 = Hmac<Sha256>;

pub const ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
pub const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

/// What most tests run as. A non-AWS region on purpose: nothing in this crate may
/// assume the AWS naming, and it is the shape the signature is checked against.
pub const REGION: my_s3::S3Region = my_s3::S3Region::HetznerFsn1;

/// Everything one request looked like once it arrived.
#[derive(Debug, Clone)]
pub struct Captured {
    pub method: String,
    /// The request target exactly as it came off the wire, e.g. `/bucket/a/b.bin`.
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Whether all of the `Content-Length` bytes actually arrived. `false` is what a
    /// body that stopped early looks like from here - the producer gave up, or the
    /// connection went away mid-request.
    pub body_complete: bool,
    /// Whether the `Authorization` header verifies against the body and headers as
    /// received.
    pub signature_valid: bool,
}

impl Captured {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn has_header(&self, name: &str) -> bool {
        self.header(name).is_some()
    }
}

/// One queued answer.
struct Reply {
    status_code: u16,
    body: String,
    /// A `Content-Length` to announce instead of the real one, after which the
    /// connection is closed. That is the shape of a download that dies mid-object, and
    /// it is the one case a client can mistake for a complete, short file.
    lie_about_length: Option<usize>,
}

struct State {
    /// Replies to hand out in order. They take precedence over [`State::objects`], so a
    /// test can still inject whatever answer it wants at any point.
    replies: Mutex<VecDeque<Reply>>,
    captured: Mutex<Vec<Captured>>,
    /// Objects this server actually holds, keyed by request path (`/bucket/key`).
    ///
    /// Empty unless a test called [`FakeS3::put_object`], and that is what keeps the
    /// default behaviour - "200 with no body" - the same for every test that does not
    /// use it.
    objects: Mutex<HashMap<String, Vec<u8>>>,
    /// How long to sit on every answer before writing it, so a test can observe a
    /// request that is genuinely still in flight rather than racing the loopback.
    delay: Mutex<Option<Duration>>,
    /// Bodies of the `PUT`s that arrived **whole** and were answered with a 2xx, keyed
    /// by request path.
    ///
    /// Separate from [`State::objects`], which is what tests *seed* for reading: an
    /// upload that lands here is a fact about what the client sent, and mixing the two
    /// would turn "this test uploaded something" into "every later GET 404s".
    uploaded: Mutex<HashMap<String, Vec<u8>>>,
    /// Bytes to accept of the next request body before hanging up, mid-request.
    ///
    /// This is the one failure a streamed upload cannot be shown any other way: the
    /// request dies while the client is still writing it, so the producer finds out
    /// through its writer rather than through the upload's return value.
    abort_after: Mutex<Option<usize>>,
    /// Bytes to accept of the next request body before answering it - early, while the
    /// client is still writing - and then hanging up.
    ///
    /// That is how a storage refuses an upload half-way (a 500, a quota): the answer is on
    /// the wire before the body is, and the connection goes with it.
    answer_after: Mutex<Option<(usize, Reply)>>,
    /// Connections this server has accepted. `captured` only grows once a body has been
    /// read, so it cannot tell "no request was ever started" from "one is in flight";
    /// this can.
    connections_accepted: AtomicUsize,
}

/// How long an early answer is left on an open connection before hanging up.
///
/// Closing a socket that still has unread request bytes in it resets the connection, and
/// a reset can take the answer that was just written with it. So the answer is given time
/// to be read first. Nothing more is read meanwhile, so the client cannot use the pause to
/// finish its body.
const EARLY_ANSWER_LINGER: Duration = Duration::from_millis(200);

pub struct FakeS3 {
    pub endpoint: String,
    state: Arc<State>,
}

impl FakeS3 {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let state = Arc::new(State {
            replies: Mutex::new(VecDeque::new()),
            captured: Mutex::new(Vec::new()),
            objects: Mutex::new(HashMap::new()),
            delay: Mutex::new(None),
            uploaded: Mutex::new(HashMap::new()),
            abort_after: Mutex::new(None),
            answer_after: Mutex::new(None),
            connections_accepted: AtomicUsize::new(0),
        });

        let accept_state = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };

                accept_state
                    .connections_accepted
                    .fetch_add(1, Ordering::AcqRel);

                let connection_state = accept_state.clone();
                tokio::spawn(async move {
                    // Keep-alive: FlUrl pools connections, so one socket carries
                    // several requests.
                    let _ = serve_connection(stream, connection_state).await;
                });
            }
        });

        Self {
            endpoint: format!("http://{}", addr),
            state,
        }
    }

    /// Queues the next reply. Without this the server answers 200 with an empty body.
    pub fn push_reply(&self, status_code: u16, body: &str) {
        self.state.replies.lock().unwrap().push_back(Reply {
            status_code,
            body: body.to_string(),
            lie_about_length: None,
        });
    }

    /// Queues a 200 that announces `declared_length` bytes, sends `body` (which is
    /// shorter), and hangs up - a download the network cut in half. A client that takes
    /// the end of the socket for the end of the object writes out a truncated file and
    /// reports success.
    pub fn push_truncated_reply(&self, body: &str, declared_length: usize) {
        self.state.replies.lock().unwrap().push_back(Reply {
            status_code: 200,
            body: body.to_string(),
            lie_about_length: Some(declared_length),
        });
    }

    /// Stores an object, so that `HEAD` reports its size and `GET` serves it - honouring
    /// `Range`. Without this the server answers from the reply queue alone, which is
    /// enough to check what a request looked like but not that the *right bytes* came
    /// back.
    ///
    /// Queued replies still win, so error injection keeps working on a served object.
    pub fn put_object(&self, bucket_name: &str, key: &str, content: Vec<u8>) {
        self.state
            .objects
            .lock()
            .unwrap()
            .insert(format!("/{}/{}", bucket_name, key), content);
    }

    /// Makes every subsequent answer wait `delay` before it is written.
    ///
    /// This is what makes "a request is still in flight" a fact rather than a race: a
    /// test can start a read, let it time out, and know the `GET` has not been answered.
    /// `Duration::ZERO` turns it off again.
    pub fn delay_every_reply(&self, delay: Duration) {
        *self.state.delay.lock().unwrap() = if delay.is_zero() { None } else { Some(delay) };
    }

    /// The body of the `PUT` that stored `key`, if one arrived whole and was accepted.
    ///
    /// `None` is the assertion "the object was never written": a request that was
    /// refused, cut short, or never made all read the same way to a consumer, and all
    /// three must.
    pub fn uploaded_object(&self, bucket_name: &str, key: &str) -> Option<Vec<u8>> {
        self.state
            .uploaded
            .lock()
            .unwrap()
            .get(&format!("/{}/{}", bucket_name, key))
            .cloned()
    }

    /// Makes the **next** request die after `after_bytes` of its body have been read:
    /// the connection is dropped where it stands, with no answer.
    ///
    /// That is an upload the network killed halfway, which is the only way to observe a
    /// producer that is still writing when the upload is already over. Use a body large
    /// enough that the client cannot have written all of it into the socket buffers
    /// before this fires.
    pub fn abort_next_request_after(&self, after_bytes: usize) {
        *self.state.abort_after.lock().unwrap() = Some(after_bytes);
    }

    /// Makes the **next** request be answered with `status_code` and `body` after
    /// `after_bytes` of its body have been read - while the client is still writing it -
    /// and the connection then closed.
    ///
    /// The storage refusing an upload half-way. Unlike
    /// [`Self::abort_next_request_after`] the client does get an answer, so the error it
    /// reports is that answer, not a broken connection.
    pub fn answer_next_request_after(&self, after_bytes: usize, status_code: u16, body: &str) {
        *self.state.answer_after.lock().unwrap() = Some((
            after_bytes,
            Reply {
                status_code,
                body: body.to_string(),
                lie_about_length: None,
            },
        ));
    }

    /// How many connections have been accepted so far - including ones whose request has
    /// not been read yet.
    pub fn connections_accepted(&self) -> usize {
        self.state.connections_accepted.load(Ordering::Acquire)
    }

    pub fn captured(&self) -> Vec<Captured> {
        self.state.captured.lock().unwrap().clone()
    }

    pub fn request_count(&self) -> usize {
        self.state.captured.lock().unwrap().len()
    }

    pub fn client(&self) -> my_s3::S3Client {
        self.client_in_region(REGION)
    }

    /// A client configured for another region. The signature is still verified: the
    /// server reads the region back out of the credential scope, the way a real one
    /// does before checking that scope against its own endpoint.
    pub fn client_in_region(&self, region: impl Into<my_s3::S3Region>) -> my_s3::S3Client {
        my_s3::S3Client::new(ACCESS_KEY, SECRET_KEY, region, self.endpoint.as_str())
    }
}

async fn serve_connection(
    mut stream: tokio::net::TcpStream,
    state: Arc<State>,
) -> std::io::Result<()> {
    let mut buffer = Vec::new();

    loop {
        // Read until the end of the header block.
        let header_end = loop {
            if let Some(index) = find_subslice(&buffer, b"\r\n\r\n") {
                break index;
            }

            let mut chunk = [0u8; 8192];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk[..read]);
        };

        let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
        let mut lines = head.split("\r\n");

        let request_line = lines.next().unwrap_or_default().to_string();
        let mut request_line_parts = request_line.split(' ');
        let method = request_line_parts.next().unwrap_or_default().to_string();
        let target = request_line_parts.next().unwrap_or_default().to_string();

        let mut headers = Vec::new();
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_string(), value.trim().to_string()));
            }
        }

        let content_length: usize = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.parse().ok())
            .unwrap_or(0);

        let is_chunked = headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        });

        buffer.drain(..header_end + 4);

        // Armed once, consumed once: a retry test arms it for the first attempt and the
        // second attempt must be served normally.
        let abort_after = state.abort_after.lock().unwrap().take();
        let answer_after = state.answer_after.lock().unwrap().take();

        let cut_after = abort_after.or(answer_after.as_ref().map(|(after_bytes, _)| *after_bytes));

        let body: Vec<u8> = if is_chunked {
            read_chunked_body(&mut stream, &mut buffer).await?
        } else {
            let wanted = match cut_after {
                Some(after_bytes) => content_length.min(after_bytes),
                None => content_length,
            };

            while buffer.len() < wanted {
                let mut chunk = [0u8; 8192];
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            let taken = buffer.len().min(wanted);
            buffer.drain(..taken).collect()
        };

        let body_complete = is_chunked || body.len() == content_length;

        let signature_valid = verify_signature(&method, &target, &headers, &body);

        let answering_a_head = method.eq_ignore_ascii_case("HEAD");

        // Read off before `headers` is moved into the capture.
        let range = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("range"))
            .map(|(_, value)| value.clone());

        state.captured.lock().unwrap().push(Captured {
            method: method.clone(),
            target: target.clone(),
            headers,
            body: body.clone(),
            body_complete,
            signature_valid,
        });

        // Dropping the stream here is the hang-up: no status line, no answer, in the
        // middle of a request the client is still writing.
        if abort_after.is_some() {
            return Ok(());
        }

        // Answered before the body is in, then hung up. Nothing is stored: the request
        // was refused, whatever part of it arrived.
        if let Some((_, reply)) = answer_after {
            write_response(&mut stream, &Response::from(reply), answering_a_head).await?;
            tokio::time::sleep(EARLY_ANSWER_LINGER).await;
            return Ok(());
        }

        // A queued reply first: a test that injected one is testing that answer, even
        // for a path this server holds an object for.
        let queued = state.replies.lock().unwrap().pop_front();

        let response = match queued {
            Some(reply) => Response::from(reply),
            None => serve_from_objects(&state, &method, &target, range.as_deref())
                .unwrap_or_else(Response::empty_ok),
        };

        // What the storage now holds. Only a `PUT` that arrived whole and was answered
        // with a 2xx wrote anything - a 503 means the object is exactly as it was.
        if method.eq_ignore_ascii_case("PUT") && body_complete && is_success(response.status_code) {
            let path = match target.split_once('?') {
                Some((path, _)) => path,
                None => target.as_str(),
            };

            state
                .uploaded
                .lock()
                .unwrap()
                .insert(path.to_string(), body);
        }

        let lied_about_length = response.lie_about_length.is_some();

        // Copied out of the mutex before awaiting: a `MutexGuard` is not `Send` and must
        // not be held across an await point.
        let delay = *state.delay.lock().unwrap();
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }

        write_response(&mut stream, &response, answering_a_head).await?;

        // The half-sent body is only a truncation if the connection then ends; keeping
        // it open would just look like a slow server.
        if lied_about_length {
            return Ok(());
        }
    }
}

/// What actually goes back on the wire.
struct Response {
    status_code: u16,
    body: Vec<u8>,
    content_type: &'static str,
    /// Header lines beyond the framing ones - `Content-Range` for a `206`.
    extra_headers: Vec<(String, String)>,
    lie_about_length: Option<usize>,
}

impl Response {
    /// The default when nothing was queued and no object matched: what this server
    /// answered before it could hold objects at all.
    fn empty_ok() -> Self {
        Self {
            status_code: 200,
            body: Vec::new(),
            content_type: "application/xml",
            extra_headers: Vec::new(),
            lie_about_length: None,
        }
    }
}

impl From<Reply> for Response {
    fn from(reply: Reply) -> Self {
        Self {
            status_code: reply.status_code,
            body: reply.body.into_bytes(),
            content_type: "application/xml",
            extra_headers: Vec::new(),
            lie_about_length: reply.lie_about_length,
        }
    }
}

/// Answers a `GET`/`HEAD` out of [`State::objects`], or `None` to fall through to the
/// default answer.
///
/// `None` - rather than a 404 - while the store is empty is what keeps every test that
/// never calls [`FakeS3::put_object`] behaving exactly as it did before.
fn serve_from_objects(
    state: &State,
    method: &str,
    target: &str,
    range: Option<&str>,
) -> Option<Response> {
    if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
        return None;
    }

    let objects = state.objects.lock().unwrap();

    if objects.is_empty() {
        return None;
    }

    // A subresource (`?location`, `?list-type=2`) is not a request for the object.
    let path = match target.split_once('?') {
        Some((path, _)) => path,
        None => target,
    };

    let Some(content) = objects.get(path) else {
        return Some(Response {
            status_code: 404,
            body: NO_SUCH_KEY.as_bytes().to_vec(),
            content_type: "application/xml",
            extra_headers: Vec::new(),
            lie_about_length: None,
        });
    };

    let length = content.len() as u64;

    // No `Range`: the whole object. For a HEAD the body is dropped, so this is also what
    // makes `Content-Length` the object's real size.
    let Some(range) = range else {
        return Some(Response {
            status_code: 200,
            body: content.clone(),
            content_type: "application/octet-stream",
            extra_headers: Vec::new(),
            lie_about_length: None,
        });
    };

    let Some((start, end)) = parse_range(range, length) else {
        return Some(Response {
            status_code: 416,
            body: INVALID_RANGE.as_bytes().to_vec(),
            content_type: "application/xml",
            extra_headers: Vec::new(),
            lie_about_length: None,
        });
    };

    Some(Response {
        status_code: 206,
        body: content[start as usize..=end as usize].to_vec(),
        content_type: "application/octet-stream",
        extra_headers: vec![(
            "Content-Range".to_string(),
            format!("bytes {}-{}/{}", start, end, length),
        )],
        lie_about_length: None,
    })
}

const NO_SUCH_KEY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>";

const INVALID_RANGE: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>InvalidRange</Code><Message>The requested range is not satisfiable</Message></Error>";

/// `bytes=<first>-<last>` and `bytes=<first>-`, resolved against the object's length and
/// clamped to it. `None` means unsatisfiable - a `416`.
///
/// Suffix ranges (`bytes=-500`) are deliberately not supported: this crate never sends
/// one, and accepting a form the client cannot produce would only hide it if it started
/// to.
fn parse_range(value: &str, length: u64) -> Option<(u64, u64)> {
    let spec = value.trim().strip_prefix("bytes=")?;
    let (first, last) = spec.split_once('-')?;

    let start: u64 = first.trim().parse().ok()?;

    // A first byte at or past the end is the one case a real S3 answers 416 for.
    if start >= length {
        return None;
    }

    let end = match last.trim() {
        "" => length - 1,
        last => last.parse::<u64>().ok()?.min(length - 1),
    };

    if end < start {
        return None;
    }

    Some((start, end))
}

async fn read_chunked_body(
    stream: &mut tokio::net::TcpStream,
    buffer: &mut Vec<u8>,
) -> std::io::Result<Vec<u8>> {
    let mut body = Vec::new();

    loop {
        // One chunk size line, then that many bytes, then CRLF.
        let line_end = loop {
            if let Some(index) = find_subslice(buffer, b"\r\n") {
                break index;
            }
            let mut chunk = [0u8; 8192];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Ok(body);
            }
            buffer.extend_from_slice(&chunk[..read]);
        };

        let size_line = String::from_utf8_lossy(&buffer[..line_end]).into_owned();
        buffer.drain(..line_end + 2);

        let size =
            usize::from_str_radix(size_line.trim().split(';').next().unwrap_or_default(), 16)
                .unwrap_or(0);

        if size == 0 {
            // Trailing CRLF after the terminating chunk.
            while buffer.len() < 2 {
                let mut chunk = [0u8; 8192];
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            let taken = buffer.len().min(2);
            buffer.drain(..taken);
            return Ok(body);
        }

        while buffer.len() < size + 2 {
            let mut chunk = [0u8; 8192];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
        }

        let taken = buffer.len().min(size);
        body.extend(buffer.drain(..taken));
        let trailing = buffer.len().min(2);
        buffer.drain(..trailing);
    }
}

async fn write_response(
    stream: &mut tokio::net::TcpStream,
    response: &Response,
    answering_a_head: bool,
) -> std::io::Result<()> {
    let status_code = response.status_code;
    let body = response.body.as_slice();
    let reason = match status_code {
        200 => "OK",
        400 => "Bad Request",
        204 => "No Content",
        206 => "Partial Content",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        416 => "Range Not Satisfiable",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    };

    let extra: String = response
        .extra_headers
        .iter()
        .map(|(name, value)| format!("{}: {}\r\n", name, value))
        .collect();

    if let Some(declared_length) = response.lie_about_length {
        let head = format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: {}\r\n{}Connection: keep-alive\r\n\r\n",
            status_code, reason, declared_length, response.content_type, extra
        );
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body).await?;
        return stream.flush().await;
    }

    let head = if answering_a_head {
        format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: {}\r\n{}Connection: keep-alive\r\n\r\n",
            status_code,
            reason,
            body.len(),
            response.content_type,
            extra
        )
    } else if status_code == 204 {
        // 204 carries no content at all - not even a zero Content-Length - which is
        // exactly the shape a client that only accepts 200 used to trip over.
        format!("HTTP/1.1 204 {}\r\nConnection: keep-alive\r\n\r\n", reason)
    } else {
        format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: {}\r\n{}Connection: keep-alive\r\n\r\n",
            status_code,
            reason,
            body.len(),
            response.content_type,
            extra
        )
    };

    stream.write_all(head.as_bytes()).await?;

    // The answer to a HEAD carries the headers of the GET that was not made - including
    // `Content-Length` - but no body. Writing one would be read as the start of the next
    // response on this keep-alive connection.
    if !answering_a_head && status_code != 204 {
        stream.write_all(body).await?;
    }

    stream.flush().await
}

/// Recomputes the SigV4 signature from the request as received and compares it with the
/// one in `Authorization`.
fn verify_signature(method: &str, target: &str, headers: &[(String, String)], body: &[u8]) -> bool {
    let get = |name: &str| -> Option<&str> {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    };

    let Some(authorization) = get("authorization") else {
        return false;
    };
    let Some(host) = get("host") else {
        return false;
    };
    let Some(payload_hash) = get("x-amz-content-sha256") else {
        return false;
    };
    let Some(timestamp) = get("x-amz-date") else {
        return false;
    };

    // A signed payload must actually hash to what the header claims. UNSIGNED-PAYLOAD
    // opts out of that by design, which is why the streamed path uses it.
    if payload_hash != "UNSIGNED-PAYLOAD" && hex::encode(Sha256::digest(body)) != payload_hash {
        return false;
    }

    let Some(signature_part) = authorization.split("Signature=").nth(1) else {
        return false;
    };
    let expected_signature = signature_part.trim();

    // `Credential=<key>/<date>/<region>/s3/aws4_request`. The region is taken from the
    // scope rather than assumed to be `REGION`, so a client configured for any region
    // can be driven through this server; a real S3 reads it the same way and then
    // checks it against the region of the endpoint that was addressed.
    let Some(scope_region) = authorization
        .split("Credential=")
        .nth(1)
        .and_then(|credential| credential.split(',').next())
        .and_then(|credential| credential.split('/').nth(2))
    else {
        return false;
    };

    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };

    let canonical_query = canonical_query(query.unwrap_or_default());

    let canonical_request = format!(
        "{}\n{}\n{}\nhost:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n\nhost;x-amz-content-sha256;x-amz-date\n{}",
        method, path, canonical_query, host, payload_hash, timestamp, payload_hash
    );

    let date = &timestamp[..8];
    let scope = format!("{}/{}/s3/aws4_request", date, scope_region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        timestamp,
        scope,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let signing_key = derive_signing_key(SECRET_KEY, date, scope_region, "s3");
    let mut mac = HmacSha256::new_from_slice(&signing_key).unwrap();
    mac.update(string_to_sign.as_bytes());

    hex::encode(mac.finalize().into_bytes()) == expected_signature
}

/// Rebuilds the canonical query string the way a real S3 does - which is **not** the way
/// the client wrote it.
///
/// This is the half of SigV4 that catches a client encoding its query by the wrong rule.
/// The server does not take the query off the wire as-is: it decodes each name and value
/// and re-encodes them by the RFC 3986 rule SigV4 cites - unreserved is `A-Za-z0-9-_.~`,
/// everything else is `%XX` - and only then sorts. A client that sent a space as `+`
/// therefore signed `a+b` while the server signs `a%2Bb`, and the request is refused as
/// `SignatureDoesNotMatch`. Taking the pairs verbatim here would have made this server
/// agree with exactly that bug.
///
/// Decoding is percent-decoding **only**: `+` is a literal plus in an S3 query string,
/// not a space. That is what makes `prefix=a+b` a request for the prefix `a+b` rather
/// than `a b`, and it is why sending `+` for a space is two bugs rather than one.
///
/// The **path** is deliberately left alone by the caller: S3 is documented as the one
/// service that does not normalize or re-encode the URI path, so there the canonical
/// form really is the bytes that were sent.
pub fn canonical_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }

    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (
                uri_encode(&percent_decode(name)),
                uri_encode(&percent_decode(value)),
            ),
            None => (uri_encode(&percent_decode(pair)), String::new()),
        })
        .collect();

    pairs.sort_unstable();

    pairs
        .iter()
        .map(|(name, value)| format!("{}={}", name, value))
        .collect::<Vec<_>>()
        .join("&")
}

/// `%XX` back to bytes. An invalid escape is left as the literal text it is, which is
/// what keeps a malformed query a signature failure rather than a panic.
fn percent_decode(src: &str) -> Vec<u8> {
    let bytes = src.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();
            if let Some(byte) = hex.and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                result.push(byte);
                index += 3;
                continue;
            }
        }

        result.push(bytes[index]);
        index += 1;
    }

    result
}

/// SigV4's `UriEncode`, written out independently of the client's.
fn uri_encode(src: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut result = String::with_capacity(src.len());

    for byte in src {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(*byte as char)
            }
            _ => {
                result.push('%');
                result.push(HEX[(*byte >> 4) as usize] as char);
                result.push(HEX[(*byte & 0x0F) as usize] as char);
            }
        }
    }

    result
}

fn derive_signing_key(secret_key: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let mut key = format!("AWS4{}", secret_key).into_bytes();

    for part in [date, region, service, "aws4_request"] {
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(part.as_bytes());
        key = mac.finalize().into_bytes().to_vec();
    }

    key
}

fn is_success(status_code: u16) -> bool {
    (200..300).contains(&status_code)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
