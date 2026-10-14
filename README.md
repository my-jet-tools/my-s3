# my-s3

An async S3 client for AWS S3 and S3-compatible storage (Hetzner Object Storage, Ceph
RGW, MinIO, Wasabi, DigitalOcean Spaces, a private deployment). Signs with SigV4, speaks
plain HTTP over [`fl-url`](https://github.com/MyJetTools/fl-url), and holds no state
between calls.

It covers what a service actually does with object storage: put an object, get it back,
delete it, list a bucket, and make sure the bucket is there. Objects larger than memory
have a streaming path in both directions, and an object can be read as a seekable source
or written as a sink — `AsyncRead + AsyncSeek` one way, `AsyncWrite` the other — so code
written against `tokio::fs::File` works unchanged. It is deliberately not an SDK — there
is no versioning, no ACLs, no lifecycle, no presigning.

## Adding it

```toml
[dependencies]
my-s3 = { tag = "0.1.1", git = "https://github.com/MyJetTools/my-s3.git" }
```

The crate depends on `fl-url` with the `with-rust-tls` feature, because S3 is always
addressed over `https://` and `fl-url` compiles its TLS paths out without a provider
feature. `with-rust-tls` is pure Rust (no C toolchain) and builds **only on x86_64 and
aarch64**. On any other architecture, switch `my-s3`'s own dependency to `with-ring-tls`.

## A client

```rust
use my_s3::S3Client;

let s3 = S3Client::new(
    "access-key",
    "secret-key",
    "fsn1",                                    // region
    "https://fsn1.your-objectstorage.com",     // endpoint
);
```

Or from one settings value, which also names the bucket — see
[A connection string](#a-connection-string):

```rust
use my_s3::S3ConnectionString;

let s3 = S3ConnectionString::parse(&settings.s3_conn_string)?.create_client();
```

`S3Client` is cheap, `Send + Sync`, and holds no connection of its own — `fl-url` pools
those process-wide — so build one at startup and share it by reference.

**The region is not decoration.** It goes into the SigV4 credential scope of every
request, and the storage checks it against the endpoint that was addressed. Getting it
wrong is a `403` that reads like a credentials problem. Anything the catalogue does not
name becomes `S3Region::Other` and is carried through verbatim, so a private Ceph with a
region of `dc1` works without a code change.

The endpoint is used **path-style** (`https://host/bucket/key`), which is what every
S3-compatible implementation accepts; virtual-host style is not supported.

### HTTP/1.1 or HTTP/2

The endpoint decides by default: one under `your-objectstorage.com` (Hetzner Object
Storage) is talked to over **HTTP/2**, anything else over **HTTP/1.1** — AWS S3 does not
speak HTTP/2 at all. Either can be forced:

```rust
let s3 = S3Client::new(/* a Hetzner endpoint */).use_h1();   // back to HTTP/1.1
let s3 = S3Client::new(/* a MinIO behind h2 */).use_h2();    // HTTP/2 elsewhere
```

The difference is what concurrent requests cost. Over HTTP/1.1 each request in flight
holds a connection of its own; over HTTP/2 they are all multiplexed over one connection
per endpoint, so a burst of small requests costs no new TLS handshakes.

Streamed uploads — `upload_streamed`, `upload_with_writer`, `start_upload` and their
retrying variants — go over HTTP/1.1 whatever is set: `fl-url` streams a request body
over HTTP/1.1 only.

### Seeing what goes out

```rust
let s3 = S3Client::new(/* ... */).debug_to_console();
```

Prints every request as it is sent, and a failed answer's body in full — that body is the
`<Error><Code>` that says why. A successful answer is printed as a size, since it is the
object that was just downloaded. `Authorization` is never printed.

## A connection string

Everything a service needs to reach its bucket, in one settings value:

```text
Endpoint=https://fsn1.your-objectstorage.com;Region=fsn1;AccessKey=...;SecretKey=...;Bucket=my-bucket
```

```rust
use my_s3::S3ConnectionString;

let conn = S3ConnectionString::parse(&settings.s3_conn_string)?;
let s3 = conn.create_client();

s3.upload(&conn.bucket, "config.json", bytes, Duration::from_secs(30)).await?;
```

`create_client` is `S3Client::new(access_key, secret_key, region, endpoint)`, plus
`debug_to_console()` when the string says `Debug=1`. `S3ConnectionString` implements
`FromStr` too, so `settings.s3_conn_string.parse::<S3ConnectionString>()` works.

| Name | | |
| --- | --- | --- |
| `Endpoint` | required | A trailing `/` is cut off, so `https://host/` works. |
| `Region` | required | |
| `AccessKey` | required | |
| `SecretKey` | required | |
| `Bucket` | required | |
| `Prefix` | optional | The folder the keys go under. `None` when it is not given, or given empty. |
| `Debug` | optional | `1/0`, `true/false`, `yes/no` or `on/off`, in any case. Any other value is an error, not "off". |

* Pairs are separated by `;`. Empty pairs (`;;`, a trailing `;`) are skipped, and the
  whitespace around names and values is trimmed.
* A pair splits at its **first** `=` only, because a base64 secret key ends in `=`.
* An empty value of a required name counts as missing.
* Names match case-insensitively — `endpoint=` works too. The documented spelling is
  PascalCase.
* An unknown name is an error, and so is a name given twice: a typo like `Secret_Key`
  must not silently mean "no secret" and surface later as a `403`.

**`parse` never panics.** It returns an `S3ConnectionStringError` — `NotAPair`,
`UnknownName`, `GivenTwice`, `Missing`, `Empty` or `DebugNotABoolean` — whose message says
what is wrong and the shape that was expected. A console that serves several buckets
shows a bad string next to the ones that work; a service that cannot run without its
bucket calls `.expect("s3_conn_string")`.

**No secret comes back out.** The `Debug` of `S3ConnectionString` writes the secret key
as `***`, and an error never quotes a value whole. A pair without `=` may be the secret
key that lost its name, so the error shows its beginning and its length:
`abc/… (40 characters)`. An unknown name is quoted whole only while it looks like a name
— at most 16 characters, letters, digits, `_` or `-` — and like a value otherwise.

## Buckets

```rust
s3.create_bucket("my-bucket").await?;
s3.create_bucket_if_not_exists("my-bucket").await?;   // idempotent
s3.check_if_bucket_exists("my-bucket").await?;        // -> bool
s3.get_bucket_location("my-bucket").await?;           // -> S3Region
```

`create_bucket` places the bucket in the client's own region. Calling it again on a
bucket you already own is `S3Error::BucketAlreadyOwnedByYou` — which is what S3 answers
on every restart of a service that ensures its bucket at startup, so use
`create_bucket_if_not_exists` there. That one absorbs "already ours" and nothing else: a
name held by **another account** stays an error, because the bucket that exists is then
not the one you are about to write to.

`check_if_bucket_exists` answers `Ok(false)` for a `404` — "not there" is an answer — but
keeps `403` an error, since that means either that the name belongs to someone else or
that the credentials are wrong.

## Uploading

```rust
s3.upload("my-bucket", "config.json", bytes, Duration::from_secs(30)).await?;
```

Peak memory is the size of `bytes`. The timeout bounds the whole request, body included;
it is required rather than defaulted because `fl-url`'s own default of 10 seconds is a
limit on the *upload*, which silently kills any real one.

For anything whose size is not bounded by construction, stream it:

```rust
let length = tokio::fs::metadata(path).await?.len() as usize;
let mut file = tokio::fs::File::open(path).await?;
let (sender, receiver) = tokio::sync::mpsc::channel(4);   // 4 chunks of backpressure

tokio::spawn(async move {
    let mut buffer = vec![0u8; 256 * 1024];
    while let Ok(read) = file.read(&mut buffer).await {
        if read == 0 || sender.send(buffer[..read].to_vec()).await.is_err() {
            break;
        }
    }
    // dropping the sender is what terminates the body
});

s3.upload_streamed("my-bucket", "backup.tar", receiver, length, Duration::from_secs(600))
    .await?;
```

Three things the compiler will not tell you:

- **`content_length` must be exact.** It is sent as `Content-Length` (SigV4 requests are
  not accepted chunked), and HTTP/1.1 gives no way to correct it. Take the length and the
  data from one source — a file's metadata and that same handle — never compute it twice.
- **Drop the sender** after the last chunk. That is how the body ends.
- **The request is attempted once.** `fl-url`'s retries do not apply to a body that is
  consumed as it is sent. Ask `S3Error::is_retryable`, rebuild the payload from the
  start, and try again — or let `upload_streamed_with_retries` run that loop for you. Its
  closure hands back a *fresh* channel per attempt, which is what makes it impossible to
  accidentally resume a half-drained source.

Retrying an upload is safe: `PutObject` replaces the whole object atomically, so a failed
attempt leaves either the previous object or nothing, never half of one.

If the producer is code that writes into a `tokio::io::AsyncWrite` rather than into a
channel — most things that already know how to write a file — use `upload_with_writer`
instead; see [Writing an object like a file](#writing-an-object-like-a-file).

A streamed body is signed as `UNSIGNED-PAYLOAD` — the signature covers the verb, path and
headers, but not the body, whose hash is not knowable before the body exists. Integrity
therefore rests on TLS, so use an `https` endpoint. AWS and Ceph both accept this.

## Downloading

Every read is a stream: `download_file` and `download_file_range` both return an
`S3DownloadStream`, and the object is held in memory only if the caller collects it.

```rust
let mut stream = s3.download_file("my-bucket", "video.mp4").await?;

// Everything an HTTP response needs in order to forward this.
let length = stream.content_length;                 // Option<u64>
let content_type = stream.content_type.as_deref();  // Option<&str>

while let Some(chunk) = stream.get_next_chunk().await? {
    sink.write_all(&chunk).await?;
}
```

This returns as soon as the response *head* has arrived, so peak memory is one chunk
whatever the object's size — a server can forward an object it could never hold. A
failure is still typed: a non-2xx body is small (it is the `<Error><Code>`) and is read,
and only a successful answer is left streaming.

Wanting the object as one `Vec<u8>` is a loop the caller writes:

```rust
let mut stream = s3.download_file("my-bucket", "config.json").await?;
let mut bytes = Vec::new();
while let Some(chunk) = stream.get_next_chunk().await? {
    bytes.extend_from_slice(&chunk);
}
```

`download_file_range` takes **inclusive** byte offsets, following the HTTP `Range`
semantics: `(0, Some(99))` is the first 100 bytes, and `end = None` reads to the end.
Its stream's `content_length` is the length of the range. A server that ignores `Range`
and answers `200` with the whole object is reported as an error rather than silently
handing back far more data than was asked for.

```rust
let mut stream = s3.download_file_range("my-bucket", "video.mp4", 0, Some(1023)).await?;
```

**A body that ends early is an `Err`, never `Ok(None)`.** A connection that breaks
mid-object must not look like the end of one, or a truncated file gets written out and
believed. The transport reports a short body as a read error, and `S3DownloadStream`
additionally counts the bytes and refuses to report the end of a stream that delivered
fewer than `Content-Length` promised.

The connection is checked out for as long as the stream lives: read it to the end and it
returns to the pool, drop it early and it is disposed of.

```rust
s3.delete_file("my-bucket", "config.json").await?;
```

Deleting is idempotent — a key that was not there is a success, not `KeyNotFound`.

S3 has no rename. Moving an object is a copy to the new key and a delete of the old one:

```rust
s3.copy_file("my-bucket", "drafts/report.pdf", "my-bucket", "published/report.pdf").await?;
s3.delete_file("my-bucket", "drafts/report.pdf").await?;
```

`copy_file` is one `CopyObject` on the storage's side — the bytes never pass through the
client — and copies at most 5 GB; a larger object needs a multipart `UploadPartCopy`,
which is not implemented. The metadata is copied with the object. A missing source is
`KeyNotFound`. A copy can fail after the storage has already answered `200 OK`, with an
`<Error>` in the body: that is reported as an error, and only a complete
`<CopyObjectResult>` counts as a copy. Hetzner Object Storage copies only within one
bucket, and says a copy "may fail depending on internal factors" — such an error is
returned as it is, and `is_retryable()` tells whether repeating it makes sense.

## Reading an object like a file

`open_reader` hands back an `S3Reader`, which implements `tokio::io::AsyncRead` and
`tokio::io::AsyncSeek`. Code written against `tokio::fs::File` — seek to an offset, read
a fixed-size page — reads an object out of S3 unchanged.

```rust
use tokio::io::{AsyncReadExt, AsyncSeekExt};

let mut reader = s3.open_reader("my-bucket", "index.dat").await?;

let mut page = vec![0u8; 16 * 1024];
reader.seek(std::io::SeekFrom::Start(4 * 16 * 1024)).await?;
reader.read_exact(&mut page).await?;
```

Opening costs **one `HEAD`**, for the size — `get_object_size` is the same call on its
own. After that:

- **Seeking is free.** It moves a number and makes no request. `Start`, `Current` and
  `End` all work, since the size is known. Seeking past the end is allowed, exactly as
  it is on a file; reading there returns nothing.
- **Each read is exactly one ranged `GET`**, for `min(what you asked for, what is left)`
  bytes. Nothing is read ahead and nothing is cached, so a `read_exact` of a 16 KiB page
  is one `GET` of 16 KiB, and the object is never held in memory whatever its size.

That last point cuts both ways: this is the shape for reading *pages* out of a large
object, not for reading one front to back in small pieces — that would be one request
per piece. Use `download_file` for that.

A reader is a single position with one request in flight, like a file handle. To read
two places at once, open two readers — another `HEAD` each, and then fully independent.
Both are `Send + Unpin`, so they move onto other tokio tasks.

**A key that is not there fails at `open_reader`**, as `S3Error::KeyNotFound`, rather
than at the first read — "there is no such object" is an ordinary answer to opening one,
and a consumer should not have to dig it out of an `io::Error`.

**A short answer is an error, never a short read.** A body that delivers less than the
range it acknowledged comes back as `io::ErrorKind::UnexpectedEof`, and a server that
ignores `Range` and returns the whole object is an error too. A caller that asked for a
page and silently got half of one would parse the half as though it were the page.

Once reading, failures arrive as `io::Error`, because that is what the traits return —
but the typed error survives as the source:

```rust
if let Some(err) = err.get_ref().and_then(|err| err.downcast_ref::<my_s3::S3Error>()) {
    if err.is_retryable() {
        // a transport failure, not a refusal
    }
}
```

`KeyNotFound` is the one that is mapped rather than wrapped: it becomes
`io::ErrorKind::NotFound`, the same answer a missing file gives.

## Writing an object like a file

`upload_with_writer` is `open_reader` the other way round. It hands a producer an
`S3UploadWriter` — a `tokio::io::AsyncWrite` — so code that already knows how to write a
file writes an S3 object with no adapter, and the object is never held in memory.

```rust
use tokio::io::AsyncWriteExt;

let path = std::path::PathBuf::from("backup.tar");
let length = tokio::fs::metadata(&path).await?.len() as usize;

s3.upload_with_writer(
    "my-bucket",
    "backup.tar",
    length,
    Duration::from_secs(600),
    |mut writer| async move {
        let mut file = tokio::fs::File::open(&path).await?;
        tokio::io::copy(&mut file, &mut writer).await?;
        writer.shutdown().await          // sends the last chunk and ends the body
    },
)
.await?;
```

Anything shaped like `write_to(&mut impl AsyncWrite)` drops straight in — the producer
never learns it is talking to S3. It does run on a task of its own, so its future must be
`Send + 'static`: move in (or `Arc`) whatever it reads from, as the `path` above is, rather
than borrowing the caller's locals.

Underneath it *is* `upload_streamed`: the writer fills a 512 KiB chunk, the chunk goes
into the same bounded channel, and the same single request sends it. The producer runs
concurrently with the upload — it has to, since the channel is bounded and the upload is
what drains it — and the call returns only once both have finished. Peak memory is a
handful of chunks — the four queued in the channel, one waiting to join them, the one the
HTTP client is writing, and the buffer being filled — at most about 3.5 MiB, whatever the
size of the object.

- **`content_length` must be exact**, for the same reason as in `upload_streamed`. Here
  the writer enforces it too: the byte that would go past it is refused with
  `io::ErrorKind::InvalidInput` and never sent, rather than quietly dropped.
- **End with `shutdown`.** It sends the last partial chunk and ends the body, and it is
  the only ending that does not depend on how the producer happened to write. A producer
  that returns with a partial chunk still buffered has not sent everything it declared,
  and gets an error for it, never a success.
- **Retries re-run the producer**, with a fresh writer, from the beginning —
  `upload_with_writer_with_retries` runs that loop on the same terms as
  `upload_streamed_with_retries`. A streamed body is consumed as it is sent, so there is
  nothing to resume from.

When something goes wrong both halves fail, and they say different things, so which one
comes back matters:

| What happened | What you get |
| --- | --- |
| The producer failed on its own | `S3Error::UploadProducerFailed` with its `io::Error` — never the storage's complaint about a short body, which is only the consequence. Not retryable: the source is what has to change. |
| The upload died while the producer was still writing | The **S3 error** that says why. The producer sees `io::ErrorKind::BrokenPipe`, which is how it finds out to stop, but `BrokenPipe` explains nothing and is not what surfaces. |
| The producer returned `Ok` but not every declared byte went out | `S3Error::UploadProducerFailed` with `io::ErrorKind::UnexpectedEof`, never a success — a source that ended early, or a missing `shutdown` that left the last chunk unsent. |

```rust
if let Some(err) = err.get_upload_producer_error() {
    // our side: a file that vanished, a length that was wrong
} else if err.is_retryable() {
    // the storage's side, and worth another attempt
}
```

### Handing the writer out

`upload_with_writer` keeps the writer inside a closure and the result in its return value,
which suits one producer writing one object from start to finish. When the writer has to
go somewhere else — a factory hands it to code that only knows `AsyncWrite`, and the
question "did it land?" comes up later — `start_upload` gives the two back separately:
an `S3UploadWriter`, and an `S3UploadHandle` whose `finish()` is the answer.

A multi-file archive is the typical shape: it asks a factory for each file, writes it, ends
it, and moves on.

```rust
use std::sync::Mutex;
use tokio::io::AsyncWriteExt;

struct ArchiveFilesInS3 {
    s3: my_s3::S3Client,
    prefix: String,
    // Collected while the archive is written, finished once it is.
    uploads: Mutex<Vec<my_s3::S3UploadHandle>>,
}

impl ArchiveFilesInS3 {
    async fn create_data_file(&self, no: u8, len: u64) -> std::io::Result<my_s3::S3UploadWriter> {
        let len = usize::try_from(len).map_err(std::io::Error::other)?;
        let key = format!("{}.data{:02X}", self.prefix, no);

        let (writer, handle) =
            self.s3.start_upload("my-bucket", &key, len, Duration::from_secs(600));

        self.uploads.lock().unwrap().push(handle);
        Ok(writer)
    }
}

// The archive writes a file and ends it - it never learns the file is an S3 object.
let mut file = files.create_data_file(0, bytes.len() as u64).await?;
file.write_all(&bytes).await?;
file.shutdown().await?;                  // sends the last chunk and ends the body

// Afterwards - and only then - each object is known to be there.
let uploads = std::mem::take(&mut *files.uploads.lock().unwrap());
for upload in uploads {
    upload.finish().await?;
}
```

The writer is the same `S3UploadWriter` as above, with the same rules — the exact length,
ending with `shutdown` — and a few more that come from the result living elsewhere:

- **Nothing goes out before the first chunk.** The request starts when the writer hands
  over its first chunk or ends the body, so a writer taken early holds no socket, and
  `upload_timeout` covers the request itself, not the wait before it. Once started, each
  upload holds a connection of its own until its answer is read.
- **Call `finish` after `shutdown`** (or after the writer has been dropped). It waits for
  the upload, which normally ends with the body, so while the writer still owes bytes it
  waits for the writer — returning sooner only if the upload fails first. Before the
  writer has handed over its first chunk nothing bounds that wait: `upload_timeout` has not
  started, and a `finish` awaited on the task that holds such a writer never returns.
- **`finish` is the only proof.** `shutdown` returning `Ok` means the body was handed over,
  not that the storage has it.
- **Dropping the handle cancels the upload**, and the writer's next write fails with
  `BrokenPipe` — an object nobody waits for does not quietly land. Dropping the handles
  above on an early `?` cancels whatever has not been answered yet; an upload whose whole
  body already went out may have landed regardless, so after a drop the object may or may
  not be there.
- **Nothing is retried.** When `finish` says `is_retryable()`, call `start_upload` again
  and write the body from the first byte.
- `start_upload` runs its request on a spawned task, so it must be called inside a tokio
  runtime. The writer and the handle are both `Send`, and may live on different tasks.

`finish` settles failures by the same rules as `upload_with_writer`, with one addition: the
handle knows only how many bytes went out, not why the code writing them stopped. A body
ended short is `UploadProducerFailed` with `UnexpectedEof`; if the writing failed for a
reason of its own, that error is the more precise one to keep.

## Listing a bucket

```rust
use my_s3::S3ListObjectsRequest;

let page = s3.list_objects_v2("my-bucket", S3ListObjectsRequest {
    prefix: Some("photos/"),
    delimiter: Some("/"),
    ..Default::default()
}).await?;

for folder in &page.common_prefixes {         // "photos/2023/", "photos/2024/"
    println!("dir  {}", folder);
}
for object in &page.objects {
    println!("file {} ({} bytes)", object.key, object.size);
}
```

With a `delimiter` this is a directory listing; without one it is a flat walk of every
key under the prefix. A `common_prefix` is a **full** prefix ending in the delimiter, so
it goes straight back in as the next request's `prefix` with no stitching.

Each `S3ObjectInfo` carries `key` (full, and already XML-unescaped), `size`,
`last_modified` (the storage's own ISO-8601 string) and `etag` (as sent, quotes
included).

**A page is not the bucket.** S3 caps a page at 1000 entries and may answer with fewer
for reasons of its own, so `next_continuation_token` — not the number of entries — is what
says whether to ask again:

```rust
let mut token = None;

loop {
    let page = s3.list_objects_v2("my-bucket", S3ListObjectsRequest {
        prefix: Some("photos/"),
        delimiter: Some("/"),
        continuation_token: token.as_deref(),
        ..Default::default()
    }).await?;

    // ... use page.common_prefixes and page.objects ...

    token = page.next_continuation_token;
    if token.is_none() {
        break;
    }
}
```

The `prefix` and `delimiter` must be repeated unchanged on every page — a continuation
token resumes a listing, it does not describe one.

A parameter left as `None` is not sent at all. That matters: S3 reads `delimiter=` as
"with an empty delimiter", which is a different request from no delimiter and would
flatten a listing that wanted folders.

Two answers are refused rather than passed on, because both would silently under-report a
bucket: a truncated page with no continuation token, and a body that was cut short by a
dropped connection.

## Errors

Every call returns `Result<_, S3Error>`. The variant is taken from the `<Error><Code>` in
the body rather than from the status code, because the status alone is ambiguous — `404`
is `NoSuchKey` as often as `NoSuchBucket`, `409` is `BucketAlreadyExists` as often as
`BucketAlreadyOwnedByYou`.

```rust
match s3.download_file("my-bucket", "maybe.json").await {
    Ok(stream) => { /* ... */ }
    Err(err) if err.is_key_not_found() => { /* no data is not a failure */ }
    Err(err) if err.is_retryable() => { /* try again */ }
    Err(err) => return Err(err),
}
```

Predicates: `is_key_not_found`, `is_bucket_not_found`, `is_bucket_already_exists`,
`is_bucket_already_owned_by_you`, `bucket_name_is_taken` (either of the last two),
`is_no_such_upload`, `is_entity_too_small`, `is_range_not_satisfiable`,
`is_upload_producer_failed`.

One variant is not the storage's answer at all: `UploadProducerFailed` is *our* side of
an `upload_with_writer` or a `start_upload` — the body could not be produced, or was ended
short. `get_upload_producer_error()`
hands back the `io::Error` that says why, and it is never retryable, because what has to
change is local.

`get_status_code()` gives the number for an unmapped answer, and `is_retryable()` answers
whether repeating the same request could plausibly succeed: 5xx, 429, a transport
failure, and the codes S3 asks for a retry by name (`SlowDown`, `RequestTimeout`,
`RequestTimeTooSkewed`, `InternalError`, `ServiceUnavailable`). A timeout counts as
retryable — for a large upload that usually means the timeout was too small, and retrying
without raising it will just time out again.

## Notes

**Signing.** Requests are signed from the url `fl-url` actually built, not from a
separately formatted bucket/key pair, so the signed bytes and the sent bytes are the same
bytes by construction. Query parameters are URI-encoded to the RFC 3986 rule SigV4 cites
rather than the `x-www-form-urlencoded` rule an HTTP client normally uses — a space is
`%20`, not `+` — because the storage rebuilds the canonical query the same way and a `+`
there is both a listing that comes back empty and a `SignatureDoesNotMatch`.

**Responses are not trusted.** Every body is bytes the server chose, so nothing in the
XML reading path may panic on one: a truncated document, a proxy's HTML page, invalid
UTF-8 and a stray closing tag are all reported as errors.

**Testing.** `cargo test` runs the suite against an S3-compatible server that runs inside
the test process (`tests/fake_s3`), over a real socket. It re-derives every signature with
its own code rather than calling into the crate — including rebuilding the canonical query
the way a real S3 does — so a test that passes is not one that agreed with a bug.
