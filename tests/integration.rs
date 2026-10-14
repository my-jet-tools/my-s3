//! End-to-end tests against an in-process S3-compatible server (`fake_s3`).
//!
//! These cover the things that are only observable on the wire and that unit tests
//! cannot reach: whether the signature verifies against the request as sent, what the
//! request target looks like, how the body is framed, and how status codes map onto
//! typed errors.

mod fake_s3;

use std::time::Duration;

use fake_s3::FakeS3;
use sha2::Digest;
use tokio::io::AsyncWriteExt;

const UPLOAD_TIMEOUT: Duration = Duration::from_secs(30);

fn no_such_key_xml() -> &'static str {
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>"
}

/// Pushes `content` through a channel the way a caller is expected to, and hands back
/// the receiver.
/// Every read comes back as a stream; this is what a caller that wants it as one `Vec<u8>`
/// writes.
async fn read_to_end(mut stream: my_s3::S3DownloadStream) -> Vec<u8> {
    let mut body = Vec::new();
    while let Some(chunk) = stream.get_next_chunk().await.unwrap() {
        body.extend_from_slice(&chunk);
    }
    body
}

fn body_from(content: Vec<u8>, chunk_size: usize) -> tokio::sync::mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = tokio::sync::mpsc::channel(4);

    tokio::spawn(async move {
        for chunk in content.chunks(chunk_size) {
            if sender.send(chunk.to_vec()).await.is_err() {
                break;
            }
        }
        // Dropping the sender terminates the body.
    });

    receiver
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// The signature has to verify against the request *as received*. This is what catches
/// signing a URL that was built differently from the one sent - the failure mode there
/// is a 403 that looks like bad credentials.
#[tokio::test]
async fn buffered_upload_is_signed_correctly() {
    let server = FakeS3::start().await;
    let client = server.client();

    client
        .upload(
            "my-bucket",
            "hello.txt",
            b"hello world".to_vec(),
            UPLOAD_TIMEOUT,
        )
        .await
        .unwrap();

    let captured = server.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].method, "PUT");
    assert_eq!(captured[0].target, "/my-bucket/hello.txt");
    assert_eq!(captured[0].body, b"hello world");
    assert!(
        captured[0].signature_valid,
        "signature did not verify: {:?}",
        captured[0]
    );
}

/// An `http://` endpoint used to break signing: the host was derived by stripping only
/// `https://`, so the signed host kept the scheme while the `Host` header did not.
/// Every test here runs over `http://`, so this asserts the specific consequence.
#[tokio::test]
async fn host_is_signed_as_sent_for_a_plain_http_endpoint() {
    let server = FakeS3::start().await;
    let client = server.client();

    let stream = client
        .download_file("my-bucket", "hello.txt")
        .await
        .unwrap();
    read_to_end(stream).await;

    let captured = server.captured();
    assert!(captured[0].signature_valid);

    // The signed host must be the Host header, port included.
    let host = captured[0].header("host").unwrap();
    assert!(host.starts_with("127.0.0.1:"), "got {:?}", host);
    assert!(!host.contains("http"), "got {:?}", host);
}

/// An endpoint that is not a usable url is bad input: the call fails at once, without a
/// retry, and the error says what is wrong with the url so it can be fixed.
#[tokio::test]
async fn an_unusable_endpoint_is_an_error_saying_why() {
    let client = my_s3::S3Client::new("access-key", "secret-key", "eu-west-1", "http://");

    let err = client
        .download_file("my-bucket", "hello.txt")
        .await
        .unwrap_err();

    assert!(
        err.to_string()
            .contains("Invalid url 'http://': it names no host"),
        "got {}",
        err
    );
    assert!(!err.is_retryable(), "bad input must not be retried");
}

/// A client built from a connection string talks to the storage with what the string
/// says: the signature verifies only with its secret key and region, the access key is
/// the one in the credential, and the request reaches its bucket - through an endpoint
/// written with a trailing `/`.
#[tokio::test]
async fn a_client_from_a_connection_string_is_signed_with_its_values() {
    let server = FakeS3::start().await;

    let connection_string: my_s3::S3ConnectionString = format!(
        "Endpoint={}/;Region={};AccessKey={};SecretKey={};Bucket=my-bucket",
        server.endpoint,
        fake_s3::REGION,
        fake_s3::ACCESS_KEY,
        fake_s3::SECRET_KEY
    )
    .parse()
    .unwrap();

    connection_string
        .create_client()
        .upload(
            connection_string.bucket.as_str(),
            "hello.txt",
            b"hello".to_vec(),
            UPLOAD_TIMEOUT,
        )
        .await
        .unwrap();

    let captured = server.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].target, "/my-bucket/hello.txt");
    assert!(
        captured[0].signature_valid,
        "signature did not verify: {:?}",
        captured[0]
    );

    let authorization = captured[0].header("authorization").unwrap();
    assert!(
        authorization.contains(&format!("Credential={}/", fake_s3::ACCESS_KEY)),
        "got {:?}",
        authorization
    );
    assert_eq!(
        server.uploaded_object("my-bucket", "hello.txt").as_deref(),
        Some(b"hello".as_slice())
    );
}

/// Keys with slashes must go out as a path so objects appear as folders in the bucket -
/// percent-encoding the separator would create one object literally named `a%2Fb`.
#[tokio::test]
async fn a_key_with_slashes_stays_a_path() {
    let server = FakeS3::start().await;
    let client = server.client();

    client
        .upload(
            "my-bucket",
            "archives/2024/06/backup.tar",
            b"x".to_vec(),
            UPLOAD_TIMEOUT,
        )
        .await
        .unwrap();

    let captured = server.captured();
    assert_eq!(captured[0].target, "/my-bucket/archives/2024/06/backup.tar");
    assert!(captured[0].signature_valid);
}

/// A key containing a space is percent-encoded on the wire, so the signature has to be
/// computed over the encoded form. Signing the raw key produced a 403.
#[tokio::test]
async fn a_key_needing_percent_encoding_is_signed_in_its_encoded_form() {
    let server = FakeS3::start().await;
    let client = server.client();

    client
        .upload(
            "my-bucket",
            "my folder/a file.txt",
            b"x".to_vec(),
            UPLOAD_TIMEOUT,
        )
        .await
        .unwrap();

    let captured = server.captured();
    assert_eq!(captured[0].target, "/my-bucket/my%20folder/a%20file.txt");
    assert!(
        captured[0].signature_valid,
        "signature must cover the encoded path"
    );
}

// ---------------------------------------------------------------------------
// Streamed upload
// ---------------------------------------------------------------------------

/// The whole point: the body arrives complete, framed by Content-Length rather than
/// chunked, because a SigV4 request is not accepted chunked.
#[tokio::test]
async fn streamed_upload_sends_content_length_and_the_whole_body() {
    let server = FakeS3::start().await;
    let client = server.client();

    // Several chunks, and a size that is not a multiple of the chunk size.
    let content: Vec<u8> = (0..200_000u32).map(|index| (index % 251) as u8).collect();

    client
        .upload_streamed(
            "my-bucket",
            "archives/big.bin",
            body_from(content.clone(), 64 * 1024),
            content.len(),
            UPLOAD_TIMEOUT,
        )
        .await
        .unwrap();

    let captured = server.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].method, "PUT");
    assert_eq!(captured[0].target, "/my-bucket/archives/big.bin");

    assert_eq!(
        captured[0].header("content-length"),
        Some(content.len().to_string().as_str())
    );
    assert!(
        !captured[0].has_header("transfer-encoding"),
        "a SigV4 request must not go out chunked"
    );

    assert_eq!(captured[0].body.len(), content.len());
    assert_eq!(captured[0].body, content);
}

/// The streamed path cannot hash a payload it has not produced yet, so it declares
/// `UNSIGNED-PAYLOAD`. Asserted explicitly because it is a real (if accepted) reduction
/// in what the signature covers.
#[tokio::test]
async fn streamed_upload_declares_an_unsigned_payload_and_still_signs_the_rest() {
    let server = FakeS3::start().await;
    let client = server.client();

    client
        .upload_streamed(
            "my-bucket",
            "a.bin",
            body_from(b"payload".to_vec(), 4),
            7,
            UPLOAD_TIMEOUT,
        )
        .await
        .unwrap();

    let captured = server.captured();
    assert_eq!(
        captured[0].header("x-amz-content-sha256"),
        Some("UNSIGNED-PAYLOAD")
    );
    // Headers, verb and path are still covered.
    assert!(captured[0].signature_valid);
}

#[tokio::test]
async fn streamed_upload_maps_a_failure_to_a_typed_error() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        403,
        "<Error><Code>AccessDenied</Code><Message>no</Message></Error>",
    );

    let err = client
        .upload_streamed(
            "my-bucket",
            "a.bin",
            body_from(b"payload".to_vec(), 4),
            7,
            UPLOAD_TIMEOUT,
        )
        .await
        .unwrap_err();

    assert_eq!(err.get_status_code(), Some(403));
    assert!(!err.is_retryable(), "403 must not be retried");
}

// ---------------------------------------------------------------------------
// Retries around the streamed upload
// ---------------------------------------------------------------------------

/// A streamed body is attempted exactly once by FlUrl, so the retry has to re-run the
/// whole thing - including re-reading the payload from the beginning.
#[tokio::test]
async fn retries_resend_the_whole_payload_after_a_retryable_failure() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        503,
        "<Error><Code>ServiceUnavailable</Code><Message>later</Message></Error>",
    );

    let content = vec![7u8; 100_000];

    client
        .upload_streamed_with_retries(
            "my-bucket",
            "a.bin",
            content.len(),
            UPLOAD_TIMEOUT,
            3,
            || body_from(vec![7u8; 100_000], 16 * 1024),
        )
        .await
        .unwrap();

    let captured = server.captured();
    assert_eq!(captured.len(), 2, "expected one failure and one success");

    // Both attempts must carry the complete payload - a resumed reader would send the
    // second attempt short.
    for attempt in &captured {
        assert_eq!(attempt.body.len(), content.len());
        assert_eq!(attempt.body, content);
    }
}

/// A deterministic failure must not be retried at all: repeating it only burns the
/// payload again.
#[tokio::test]
async fn a_non_retryable_failure_is_attempted_once() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        403,
        "<Error><Code>AccessDenied</Code><Message>no</Message></Error>",
    );

    let err = client
        .upload_streamed_with_retries("my-bucket", "a.bin", 8, UPLOAD_TIMEOUT, 5, || {
            body_from(b"contents".to_vec(), 4)
        })
        .await
        .unwrap_err();

    assert_eq!(err.get_status_code(), Some(403));
    assert_eq!(server.request_count(), 1, "403 must not be retried");
}

#[tokio::test]
async fn retries_give_up_and_return_the_last_error() {
    let server = FakeS3::start().await;
    let client = server.client();

    for _ in 0..4 {
        server.push_reply(
            503,
            "<Error><Code>ServiceUnavailable</Code><Message>later</Message></Error>",
        );
    }

    let err = client
        .upload_streamed_with_retries("my-bucket", "a.bin", 8, UPLOAD_TIMEOUT, 2, || {
            body_from(b"contents".to_vec(), 4)
        })
        .await
        .unwrap_err();

    assert_eq!(err.get_status_code(), Some(503));
    assert!(err.is_retryable());
    // 1 initial attempt + 2 retries
    assert_eq!(server.request_count(), 3);
}

// ---------------------------------------------------------------------------
// Uploading through an AsyncWrite
// ---------------------------------------------------------------------------

/// Content with no repeating period, so a chunk that arrived twice or in the wrong
/// order cannot compare equal by luck.
fn pattern(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index % 251) as u8).collect()
}

/// A writer is only useful to a producer that can move it onto another task, which is
/// exactly what `upload_with_writer` does to it - and what a factory handing out writers
/// from `start_upload` does. `Unpin` is what lets `write_all` and `tokio::io::copy` take it
/// by `&mut` without pinning it first.
#[test]
fn the_writer_is_send_and_unpin() {
    fn assert_send_and_unpin<T: Send + Unpin>() {}

    assert_send_and_unpin::<my_s3::S3UploadWriter>();
}

/// The pathological producer: one byte per call, so every path through `poll_write` is
/// taken thousands of times and the final partial chunk is the only thing `shutdown`
/// has to send.
#[tokio::test]
async fn writer_upload_delivers_the_object_written_one_byte_at_a_time() {
    let server = FakeS3::start().await;
    let client = server.client();

    let content = pattern(3_000);
    let expected = content.clone();

    client
        .upload_with_writer(
            "my-bucket",
            "archives/tiny.bin",
            content.len(),
            UPLOAD_TIMEOUT,
            |mut writer| async move {
                for byte in &content {
                    writer.write_all(&[*byte]).await?;
                }
                writer.shutdown().await
            },
        )
        .await
        .unwrap();

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/tiny.bin"),
        Some(expected)
    );
}

/// Writes smaller than the chunk size, over a body several chunks long: the interesting
/// part is the boundaries, where a write is split between the chunk being sent and the
/// one being started.
#[tokio::test]
async fn writer_upload_delivers_the_object_written_in_small_pieces() {
    let server = FakeS3::start().await;
    let client = server.client();

    // Deliberately not a multiple of the 512 KiB chunk size, nor of the write size.
    let content = pattern(1_500_000);
    let expected = content.clone();

    client
        .upload_with_writer(
            "my-bucket",
            "archives/pieces.bin",
            content.len(),
            UPLOAD_TIMEOUT,
            |mut writer| async move {
                for piece in content.chunks(7_000) {
                    writer.write_all(piece).await?;
                }
                writer.shutdown().await
            },
        )
        .await
        .unwrap();

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/pieces.bin"),
        Some(expected)
    );
}

/// One write far larger than a chunk. `poll_write` answers it with a partial write per
/// chunk, so this is really a test that `write_all` and the writer agree about how many
/// bytes were taken - an off-by-one there duplicates or drops a chunk's worth.
#[tokio::test]
async fn writer_upload_delivers_the_object_written_in_one_multi_megabyte_write() {
    let server = FakeS3::start().await;
    let client = server.client();

    let content = pattern(3 * 1024 * 1024);
    let expected = content.clone();

    client
        .upload_with_writer(
            "my-bucket",
            "archives/one-write.bin",
            content.len(),
            UPLOAD_TIMEOUT,
            |mut writer| async move {
                writer.write_all(&content).await?;
                writer.shutdown().await
            },
        )
        .await
        .unwrap();

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/one-write.bin"),
        Some(expected)
    );
}

/// The shape the README advertises, and the reason this exists at all: a producer that
/// only knows how to write into an `AsyncWrite`, copied in with no adapter.
#[tokio::test]
async fn writer_upload_works_as_the_destination_of_tokio_io_copy() {
    let server = FakeS3::start().await;
    let client = server.client();

    let content = pattern(900_000);
    let expected = content.clone();

    client
        .upload_with_writer(
            "my-bucket",
            "archives/copied.bin",
            content.len(),
            UPLOAD_TIMEOUT,
            |mut writer| async move {
                let mut source = std::io::Cursor::new(content);
                tokio::io::copy(&mut source, &mut writer).await?;
                writer.shutdown().await
            },
        )
        .await
        .unwrap();

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/copied.bin"),
        Some(expected)
    );
}

/// `Content-Length` was signed before the first byte existed and cannot be corrected, so
/// the byte that would go past it is refused rather than sent. The object must not
/// exist: half of an archive is worse than none of one.
#[tokio::test]
async fn writing_past_content_length_is_refused_and_nothing_is_stored() {
    let server = FakeS3::start().await;
    let client = server.client();

    let err = client
        .upload_with_writer(
            "my-bucket",
            "archives/over.bin",
            1_000,
            UPLOAD_TIMEOUT,
            |mut writer| async move {
                // The producer has miscounted: it declared 1 000 and has 1 500.
                writer.write_all(&pattern(1_500)).await?;
                writer.shutdown().await
            },
        )
        .await
        .unwrap_err();

    let io_error = err
        .get_upload_producer_error()
        .expect("a producer that ran past its length is the producer's failure");

    assert_eq!(io_error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(!err.is_retryable(), "writing too much cannot be retried");

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/over.bin"),
        None
    );
}

/// A producer that returns `Ok` without having written everything - the missing
/// `shutdown`, or a loop that ended a chunk early. The storage's own complaint about a
/// short body is not enough: it says the request was malformed, not that the caller
/// stopped early.
#[tokio::test]
async fn a_producer_that_stops_short_is_never_a_success() {
    let server = FakeS3::start().await;
    let client = server.client();

    let err = client
        .upload_with_writer(
            "my-bucket",
            "archives/short.bin",
            1_000,
            UPLOAD_TIMEOUT,
            |mut writer| async move {
                writer.write_all(&pattern(400)).await?;
                writer.shutdown().await
            },
        )
        .await
        .unwrap_err();

    let io_error = err
        .get_upload_producer_error()
        .expect("a body that stopped early is the producer's failure");

    assert_eq!(io_error.kind(), std::io::ErrorKind::UnexpectedEof);
    assert!(
        io_error.to_string().contains("400 of the 1000"),
        "the error has to say how far it got, got: {}",
        io_error
    );

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/short.bin"),
        None
    );
}

/// The producer's own error is the one that comes back - not the short-body error it
/// causes downstream - and it is not repeated: asking the same broken source again gets
/// the same answer.
#[tokio::test]
async fn a_producer_that_fails_surfaces_its_own_error_and_is_not_retried() {
    let server = FakeS3::start().await;
    let client = server.client();

    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = calls.clone();

    let err = client
        .upload_with_writer_with_retries(
            "my-bucket",
            "archives/broken.bin",
            1_000,
            UPLOAD_TIMEOUT,
            3,
            move |mut writer| {
                let calls = counted.clone();
                async move {
                    calls.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    writer.write_all(&pattern(100)).await?;

                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "the archive source gave up",
                    ))
                }
            },
        )
        .await
        .unwrap_err();

    let io_error = err
        .get_upload_producer_error()
        .expect("the producer's error, not the storage's");

    assert_eq!(io_error.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(io_error.to_string(), "the archive source gave up");

    assert_eq!(
        calls.load(std::sync::atomic::Ordering::Acquire),
        1,
        "a broken source must not be asked again"
    );
    assert_eq!(
        server.uploaded_object("my-bucket", "archives/broken.bin"),
        None
    );
}

/// A streamed body is consumed as it is sent, so a retry is a whole new body. The
/// producer is called again with a fresh writer and has to write from the beginning -
/// one that resumed would send the second attempt short.
#[tokio::test]
async fn a_retryable_failure_re_runs_the_producer_from_the_beginning() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        503,
        "<Error><Code>ServiceUnavailable</Code><Message>later</Message></Error>",
    );

    let content = pattern(300_000);
    let expected = content.clone();

    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = calls.clone();

    client
        .upload_with_writer_with_retries(
            "my-bucket",
            "archives/retried.bin",
            content.len(),
            UPLOAD_TIMEOUT,
            3,
            move |mut writer| {
                let calls = counted.clone();
                let content = content.clone();
                async move {
                    calls.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    writer.write_all(&content).await?;
                    writer.shutdown().await
                }
            },
        )
        .await
        .unwrap();

    assert_eq!(
        calls.load(std::sync::atomic::Ordering::Acquire),
        2,
        "one failed attempt and one that worked"
    );

    let captured = server.captured();
    assert_eq!(captured.len(), 2);

    // Both attempts carried the whole payload: the second one is what proves the
    // producer restarted rather than resumed.
    for attempt in &captured {
        assert_eq!(attempt.body.len(), expected.len());
        assert_eq!(attempt.body, expected);
        assert!(attempt.body_complete);
    }

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/retried.bin"),
        Some(expected)
    );
}

/// The upload dies while the producer is still writing. The producer has to find out -
/// otherwise it sits on a channel nobody drains and this call never returns - but what
/// it finds out is only `BrokenPipe`, which says nothing. The error that surfaces must
/// be the storage's, which says why.
#[tokio::test]
async fn an_upload_that_dies_mid_body_gives_the_producer_broken_pipe() {
    let server = FakeS3::start().await;
    let client = server.client();

    // Far more than any socket buffer will absorb, so the client is still writing when
    // the server hangs up 64 KiB in.
    let length = 32 * 1024 * 1024;
    server.abort_next_request_after(64 * 1024);

    let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
    let reported = seen.clone();

    let result = tokio::time::timeout(
        Duration::from_secs(30),
        client.upload_with_writer(
            "my-bucket",
            "archives/cut.bin",
            length,
            UPLOAD_TIMEOUT,
            move |mut writer| async move {
                let piece = vec![9u8; 64 * 1024];
                let mut written = 0;

                while written < length {
                    if let Err(err) = writer.write_all(&piece).await {
                        *reported.lock().unwrap() = Some(err.kind());
                        return Err(err);
                    }
                    written += piece.len();
                }

                writer.shutdown().await
            },
        ),
    )
    .await
    .expect("the producer has to be woken when the upload dies, or this never returns");

    let err = result.unwrap_err();

    assert_eq!(
        *seen.lock().unwrap(),
        Some(std::io::ErrorKind::BrokenPipe),
        "the producer has to see the upload go away"
    );

    assert!(
        !err.is_upload_producer_failed(),
        "the upload died first, so its own error is the one that explains this - got: {}",
        err
    );

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/cut.bin"),
        None
    );
}

/// The mistake the docs warn about most: every byte was written, `shutdown` was not
/// called, and the last partial chunk is still in the writer when it is dropped. The
/// count of bytes *accepted* equals `content_length` here, so this is exactly the case
/// that a check measuring the wrong thing lets through as a transport error - and a
/// transport error might get retried, re-running a producer that will forget again.
#[tokio::test]
async fn a_producer_that_forgets_shutdown_with_a_partial_chunk_is_never_a_success() {
    let server = FakeS3::start().await;
    let client = server.client();

    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = calls.clone();

    // One full 512 KiB chunk goes out on its own; the 188 KB tail only goes out on
    // shutdown, which never comes.
    let length = 700_000;

    let err = client
        .upload_with_writer_with_retries(
            "my-bucket",
            "archives/no-shutdown.bin",
            length,
            UPLOAD_TIMEOUT,
            3,
            move |mut writer| {
                let calls = counted.clone();
                async move {
                    calls.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    writer.write_all(&pattern(length)).await?;
                    Ok(())
                }
            },
        )
        .await
        .unwrap_err();

    let io_error = err
        .get_upload_producer_error()
        .expect("a body that never went out whole is the producer's failure, not the storage's");

    assert_eq!(io_error.kind(), std::io::ErrorKind::UnexpectedEof);
    assert!(
        io_error.to_string().contains("524288 of the 700000"),
        "the error has to say how much really went out, got: {}",
        io_error
    );

    assert_eq!(
        calls.load(std::sync::atomic::Ordering::Acquire),
        1,
        "a producer that forgets shutdown will forget it again - do not retry it"
    );
    assert_eq!(
        server.uploaded_object("my-bucket", "archives/no-shutdown.bin"),
        None
    );
}

/// The counterpart: when the length lands exactly on a chunk boundary, every chunk was
/// sent by `poll_write` itself and dropping the writer ends a body that is already
/// complete. That is a correct upload, and it must not be refused for a missing call
/// that had nothing left to send.
#[tokio::test]
async fn a_producer_that_forgets_shutdown_on_a_chunk_boundary_still_delivers() {
    let server = FakeS3::start().await;
    let client = server.client();

    let content = pattern(2 * my_s3::DEFAULT_UPLOAD_CHUNK_SIZE);
    let expected = content.clone();

    client
        .upload_with_writer(
            "my-bucket",
            "archives/boundary.bin",
            content.len(),
            UPLOAD_TIMEOUT,
            |mut writer| async move {
                writer.write_all(&content).await?;
                Ok(())
            },
        )
        .await
        .unwrap();

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/boundary.bin"),
        Some(expected)
    );
}

/// An empty object is a legitimate one - an empty archive, a marker file - and it is the
/// one case where the producer's only job is to end the body.
#[tokio::test]
async fn a_zero_length_object_is_one_put_with_an_empty_body() {
    let server = FakeS3::start().await;
    let client = server.client();

    client
        .upload_with_writer(
            "my-bucket",
            "archives/empty.bin",
            0,
            UPLOAD_TIMEOUT,
            |mut writer| async move { writer.shutdown().await },
        )
        .await
        .unwrap();

    let captured = server.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].method, "PUT");
    assert_eq!(captured[0].header("content-length"), Some("0"));
    assert!(captured[0].body_complete);

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/empty.bin"),
        Some(Vec::new())
    );
}

/// `flush` sends what is buffered without ending the body, so a producer may flush as
/// often as it likes - after every record, say - and keep writing.
#[tokio::test]
async fn flushing_mid_stream_does_not_end_the_body() {
    let server = FakeS3::start().await;
    let client = server.client();

    let content = pattern(800_000);
    let expected = content.clone();

    client
        .upload_with_writer(
            "my-bucket",
            "archives/flushed.bin",
            content.len(),
            UPLOAD_TIMEOUT,
            |mut writer| async move {
                for piece in content.chunks(100_000) {
                    writer.write_all(piece).await?;
                    writer.flush().await?;
                }
                writer.shutdown().await
            },
        )
        .await
        .unwrap();

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/flushed.bin"),
        Some(expected)
    );
}

/// After `shutdown` the body has ended and there is nowhere for more bytes to go. The
/// refusal is `BrokenPipe`, the same answer a closed socket gives - and, because the
/// producer chose to report it, the call fails even though the body itself was
/// complete: a producer's `Err` is never turned into a success.
#[tokio::test]
async fn writing_after_shutdown_is_refused() {
    let server = FakeS3::start().await;
    let client = server.client();

    let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
    let reported = seen.clone();

    let err = client
        .upload_with_writer(
            "my-bucket",
            "archives/after.bin",
            1_000,
            UPLOAD_TIMEOUT,
            move |mut writer| async move {
                writer.write_all(&pattern(1_000)).await?;
                writer.shutdown().await?;

                let err = writer
                    .write_all(b"late")
                    .await
                    .expect_err("the body has ended");
                *reported.lock().unwrap() = Some(err.kind());

                Err(err)
            },
        )
        .await
        .unwrap_err();

    assert_eq!(*seen.lock().unwrap(), Some(std::io::ErrorKind::BrokenPipe));
    assert_eq!(
        err.get_upload_producer_error().map(|err| err.kind()),
        Some(std::io::ErrorKind::BrokenPipe),
        "the producer's own error, got: {}",
        err
    );
}

/// A producer that panics has not produced the body. The panic must not take the
/// caller's task down with it, and it must not be mistaken for anything but a failure.
#[tokio::test]
async fn a_producer_that_panics_is_never_a_success() {
    let server = FakeS3::start().await;
    let client = server.client();

    let err = client
        .upload_with_writer(
            "my-bucket",
            "archives/panicked.bin",
            1_000,
            UPLOAD_TIMEOUT,
            |mut writer| async move {
                writer.write_all(&pattern(500)).await?;
                panic!("the archive source is corrupt");
            },
        )
        .await
        .unwrap_err();

    let io_error = err
        .get_upload_producer_error()
        .expect("a panicking producer is a producer failure");

    assert!(
        io_error.to_string().contains("did not finish"),
        "got: {}",
        io_error
    );
    assert!(!err.is_retryable());

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/panicked.bin"),
        None
    );
}

// ---------------------------------------------------------------------------
// Starting an upload and finishing it later
// ---------------------------------------------------------------------------

/// Writes into `writer` until it refuses a write, and hands back that refusal.
///
/// Used where the upload is expected to go away under the writer. How many writes that
/// takes is not a number to assert on - the upload keeps draining the channel until it
/// finds out - so the loop is bounded by the object's length, and running out of it
/// without a refusal fails the test.
async fn write_until_refused(writer: &mut my_s3::S3UploadWriter) -> std::io::Error {
    let piece = vec![9u8; 64 * 1024];

    while writer.bytes_written() < writer.content_length() {
        let owed = writer.content_length() - writer.bytes_written();
        let take = owed.min(piece.len() as u64) as usize;

        if let Err(err) = writer.write_all(&piece[..take]).await {
            return err;
        }
    }

    panic!("every byte was accepted - the upload never went away under the writer")
}

/// The shape the whole thing exists for: the writer is an ordinary value, and the answer
/// comes from somewhere else, later.
#[tokio::test]
async fn a_started_upload_delivers_the_object_and_finish_reports_it() {
    let server = FakeS3::start().await;
    let client = server.client();

    // Several chunks, and not a multiple of the chunk size or of the write size.
    let content = pattern(1_500_000);

    let (mut writer, handle) = client.start_upload(
        "my-bucket",
        "archives/started.bin",
        content.len(),
        UPLOAD_TIMEOUT,
    );

    for piece in content.chunks(7_000) {
        writer.write_all(piece).await.unwrap();
    }
    writer.shutdown().await.unwrap();

    handle.finish().await.unwrap();

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/started.bin"),
        Some(content.clone())
    );

    let captured = server.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].method, "PUT");
    assert_eq!(
        captured[0].header("content-length"),
        Some(content.len().to_string().as_str())
    );
    assert!(captured[0].signature_valid);
}

/// An empty object is still one request: the body ends before it has a chunk, and ending
/// it is what starts the request.
#[tokio::test]
async fn a_started_upload_of_zero_bytes_is_one_empty_put() {
    let server = FakeS3::start().await;
    let client = server.client();

    let (mut writer, handle) =
        client.start_upload("my-bucket", "archives/empty.bin", 0, UPLOAD_TIMEOUT);

    writer.shutdown().await.unwrap();
    handle.finish().await.unwrap();

    let captured = server.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].header("content-length"), Some("0"));
    assert!(captured[0].body_complete);

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/empty.bin"),
        Some(Vec::new())
    );
}

/// Ended with `shutdown`, but short of what was declared. Never a success - and a body
/// already known to be short does not cost a request the storage would only refuse.
#[tokio::test]
async fn a_started_upload_that_stops_short_is_never_a_success() {
    let server = FakeS3::start().await;
    let client = server.client();

    let (mut writer, handle) =
        client.start_upload("my-bucket", "archives/short.bin", 1_000, UPLOAD_TIMEOUT);

    writer.write_all(&pattern(400)).await.unwrap();
    writer.shutdown().await.unwrap();

    let err = handle.finish().await.unwrap_err();

    let io_error = err
        .get_upload_producer_error()
        .expect("a body ended short is the writer's failure, not the storage's");

    assert_eq!(io_error.kind(), std::io::ErrorKind::UnexpectedEof);
    assert!(
        io_error.to_string().contains("only 400 of the 1000"),
        "the error has to say how far it got, got: {}",
        io_error
    );
    assert!(!err.is_retryable());

    // Deterministic on the single-threaded test runtime: nothing above yields, so the
    // upload task first runs inside `finish`, when the body has already ended short.
    assert_eq!(server.request_count(), 0);
    assert_eq!(
        server.uploaded_object("my-bucket", "archives/short.bin"),
        None
    );
}

/// Every byte was written, but the writer was dropped instead of shut down, so the last
/// partial chunk never left it. `bytes_written` equals the declared length here - which is
/// why delivery is measured by what reached the channel.
#[tokio::test]
async fn dropping_the_writer_with_a_partial_chunk_is_reported_as_short() {
    let server = FakeS3::start().await;
    let client = server.client();

    // One full 512 KiB chunk goes out on its own; the 188 KB tail only on shutdown.
    let length = 700_000;

    let (mut writer, handle) =
        client.start_upload("my-bucket", "archives/dropped.bin", length, UPLOAD_TIMEOUT);

    writer.write_all(&pattern(length)).await.unwrap();
    assert_eq!(writer.bytes_written(), length as u64);
    drop(writer);

    let err = handle.finish().await.unwrap_err();

    let io_error = err
        .get_upload_producer_error()
        .expect("a writer dropped with a buffered chunk is the writer's failure");

    assert_eq!(io_error.kind(), std::io::ErrorKind::UnexpectedEof);
    assert!(
        io_error.to_string().contains("only 524288 of the 700000"),
        "the error has to say how much really went out, got: {}",
        io_error
    );

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/dropped.bin"),
        None
    );
}

/// The byte past the declared length is refused and never sent. The refusal itself touches
/// nothing: the 1 000 accepted bytes are still buffered, and ending the body properly
/// delivers exactly them.
#[tokio::test]
async fn writing_past_a_started_uploads_length_is_refused_and_not_sent() {
    let server = FakeS3::start().await;
    let client = server.client();

    let (mut writer, handle) =
        client.start_upload("my-bucket", "archives/over.bin", 1_000, UPLOAD_TIMEOUT);

    let err = writer.write_all(&pattern(1_500)).await.unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(writer.bytes_written(), 1_000);

    writer.shutdown().await.unwrap();
    handle.finish().await.unwrap();

    let captured = server.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].body.len(), 1_000, "not one extra byte went out");

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/over.bin"),
        Some(pattern(1_000))
    );
}

/// The same refusal, followed by what a caller that bails out on the error does: drop the
/// writer. No object now - but because the buffered 1 000 bytes never left the writer
/// (0 of 1 000 went out), not because of the refusal.
#[tokio::test]
async fn bailing_out_after_writing_past_the_length_stores_nothing() {
    let server = FakeS3::start().await;
    let client = server.client();

    let (mut writer, handle) =
        client.start_upload("my-bucket", "archives/over.bin", 1_000, UPLOAD_TIMEOUT);

    let err = writer.write_all(&pattern(1_500)).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

    drop(writer);

    let err = handle.finish().await.unwrap_err();

    let io_error = err
        .get_upload_producer_error()
        .expect("the writer's failure");
    assert_eq!(io_error.kind(), std::io::ErrorKind::UnexpectedEof);
    assert!(
        io_error.to_string().contains("only 0 of the 1000"),
        "got: {}",
        io_error
    );

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/over.bin"),
        None
    );
}

/// The storage refuses the upload half-way, with an answer. The writer only learns that the
/// upload is gone - `BrokenPipe` - and `finish` says why: the storage's own error, not
/// the pipe.
#[tokio::test]
async fn a_server_that_answers_500_mid_body_surfaces_through_finish() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.answer_next_request_after(
        64 * 1024,
        500,
        "<Error><Code>InternalError</Code><Message>We encountered an internal error.</Message></Error>",
    );

    let (mut writer, handle) = client.start_upload(
        "my-bucket",
        "archives/refused.bin",
        32 * 1024 * 1024,
        UPLOAD_TIMEOUT,
    );

    let err = tokio::time::timeout(Duration::from_secs(30), write_until_refused(&mut writer))
        .await
        .expect("the writer has to be woken when the upload dies");

    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);

    let err = handle.finish().await.unwrap_err();

    assert_eq!(
        err.get_status_code(),
        Some(500),
        "the storage's answer, not the broken pipe it caused - got: {}",
        err
    );
    assert!(!err.is_upload_producer_failed());
    assert!(err.is_retryable());

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/refused.bin"),
        None
    );
}

/// The same with no answer at all - the connection is simply cut. Still the upload's
/// failure, not the writer's.
#[tokio::test]
async fn a_connection_cut_mid_body_is_the_uploads_failure_not_the_writers() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.abort_next_request_after(64 * 1024);

    let (mut writer, handle) = client.start_upload(
        "my-bucket",
        "archives/cut.bin",
        32 * 1024 * 1024,
        UPLOAD_TIMEOUT,
    );

    let err = tokio::time::timeout(Duration::from_secs(30), write_until_refused(&mut writer))
        .await
        .expect("the writer has to be woken when the upload dies");

    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);

    let err = handle.finish().await.unwrap_err();

    assert!(
        !err.is_upload_producer_failed(),
        "the upload died first, so its own error explains this - got: {}",
        err
    );

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/cut.bin"),
        None
    );
}

/// A refusal that arrives after the whole body: the plain case, and a retryable one.
#[tokio::test]
async fn a_server_error_after_the_body_is_what_finish_returns() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        503,
        "<Error><Code>ServiceUnavailable</Code><Message>later</Message></Error>",
    );

    let (mut writer, handle) =
        client.start_upload("my-bucket", "archives/later.bin", 10_000, UPLOAD_TIMEOUT);

    writer.write_all(&pattern(10_000)).await.unwrap();
    writer.shutdown().await.unwrap();

    let err = handle.finish().await.unwrap_err();

    assert_eq!(err.get_status_code(), Some(503));
    assert!(err.is_retryable());
    assert!(!err.is_upload_producer_failed());

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/later.bin"),
        None
    );
}

/// Drops the handle of an upload whose request is genuinely in flight - the body is
/// already being drained into the socket - and checks that the upload is cancelled.
///
/// "In flight" is established rather than assumed: more chunks than the channel, the
/// pending send and the buffer can hold between them have been accepted, which only
/// happens once the request has taken some. Dropping the handle any earlier would abort a
/// task that never ran, and prove nothing about cancelling a live request.
async fn dropping_the_handle_of_an_upload_in_flight_cancels_it() {
    let server = FakeS3::start().await;
    let client = server.client();

    let (mut writer, handle) = client.start_upload(
        "my-bucket",
        "archives/cancelled.bin",
        32 * 1024 * 1024,
        UPLOAD_TIMEOUT,
    );

    let piece = vec![5u8; 64 * 1024];
    let in_flight = 8 * my_s3::DEFAULT_UPLOAD_CHUNK_SIZE as u64;

    tokio::time::timeout(Duration::from_secs(30), async {
        while writer.bytes_written() < in_flight {
            writer.write_all(&piece).await.unwrap();
        }
    })
    .await
    .expect("the request has to start draining the body");

    // Taking the chunks proves the client connected, not that the server's accept loop
    // has run yet - the kernel buffers a connection still waiting in the backlog.
    tokio::time::timeout(Duration::from_secs(30), async {
        while server.connections_accepted() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the server has to see the connection");

    assert_eq!(server.connections_accepted(), 1);

    drop(handle);

    let err = tokio::time::timeout(Duration::from_secs(30), write_until_refused(&mut writer))
        .await
        .expect("the writer has to be woken when the upload is cancelled");

    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/cancelled.bin"),
        None
    );
}

#[tokio::test]
async fn dropping_the_handle_cancels_the_upload() {
    dropping_the_handle_of_an_upload_in_flight_cancels_it().await;
}

/// The same with the upload task and the writer on different worker threads, where the
/// abort lands while both are running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_handle_cancels_the_upload_on_a_multi_threaded_runtime() {
    dropping_the_handle_of_an_upload_in_flight_cancels_it().await;
}

/// The writer feels a dropped handle at once. Aborting the task only schedules its
/// teardown, and until then the channel would still take chunks - so without this a small
/// body could be written and "ended" with `shutdown` returning `Ok`, into an upload that
/// no longer exists.
#[tokio::test]
async fn the_very_next_write_after_the_handle_is_dropped_is_refused() {
    let server = FakeS3::start().await;
    let client = server.client();

    let (mut writer, handle) =
        client.start_upload("my-bucket", "archives/at-once.bin", 1_000, UPLOAD_TIMEOUT);

    writer.write_all(&pattern(100)).await.unwrap();

    drop(handle);

    let err = writer.write_all(&pattern(100)).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);

    let err = writer.shutdown().await.unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::BrokenPipe,
        "a body cannot be ended into a cancelled upload"
    );

    drop(writer);
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(server.connections_accepted(), 0);
    assert_eq!(
        server.uploaded_object("my-bucket", "archives/at-once.bin"),
        None
    );
}

/// A handle that went through `finish` leaves its writer alone: a finished upload is not a
/// cancelled one, so a writer that is still around is not told it is.
#[tokio::test]
async fn a_finished_handle_does_not_cancel_anything_when_it_goes() {
    let server = FakeS3::start().await;
    let client = server.client();

    // Exactly one chunk: the body is complete as soon as it is sent, without `shutdown`.
    let content = pattern(my_s3::DEFAULT_UPLOAD_CHUNK_SIZE);

    let (mut writer, handle) = client.start_upload(
        "my-bucket",
        "archives/boundary.bin",
        content.len(),
        UPLOAD_TIMEOUT,
    );

    writer.write_all(&content).await.unwrap();

    tokio::time::timeout(Duration::from_secs(30), handle.finish())
        .await
        .expect("a complete body ends the upload on its own")
        .unwrap();

    // Still the writer's own answers, not a cancellation's.
    let err = writer.write_all(b"x").await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    writer.shutdown().await.unwrap();

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/boundary.bin"),
        Some(content)
    );
}

/// A handle dropped before the writer produced anything: the request was never started,
/// and is not started by the chunks that follow.
#[tokio::test]
async fn dropping_the_handle_before_the_first_chunk_never_opens_a_connection() {
    let server = FakeS3::start().await;
    let client = server.client();

    let (mut writer, handle) = client.start_upload(
        "my-bucket",
        "archives/never.bin",
        32 * 1024 * 1024,
        UPLOAD_TIMEOUT,
    );

    writer.write_all(&pattern(100)).await.unwrap();

    drop(handle);

    let err = tokio::time::timeout(Duration::from_secs(30), write_until_refused(&mut writer))
        .await
        .expect("the writer has to be woken when the upload is cancelled");

    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    assert_eq!(server.connections_accepted(), 0);
    assert_eq!(server.request_count(), 0);
}

/// Nothing touches the network until the writer has a chunk to hand over - and then the
/// request starts at once, without waiting for `shutdown`.
#[tokio::test]
async fn nothing_touches_the_network_before_the_first_chunk() {
    let server = FakeS3::start().await;
    let client = server.client();

    let content = pattern(2 * my_s3::DEFAULT_UPLOAD_CHUNK_SIZE + 1_000);
    let first_chunk = my_s3::DEFAULT_UPLOAD_CHUNK_SIZE;

    let (mut writer, handle) = client.start_upload(
        "my-bucket",
        "archives/lazy.bin",
        content.len(),
        UPLOAD_TIMEOUT,
    );

    writer.write_all(&content[..100]).await.unwrap();

    // Long enough for a spawned task to have connected, had it been going to.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(server.connections_accepted(), 0);

    writer.write_all(&content[100..first_chunk]).await.unwrap();

    tokio::time::timeout(Duration::from_secs(30), async {
        while server.connections_accepted() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the first chunk has to start the request");

    writer.write_all(&content[first_chunk..]).await.unwrap();
    writer.shutdown().await.unwrap();

    handle.finish().await.unwrap();

    assert_eq!(server.connections_accepted(), 1);
    assert_eq!(
        server.uploaded_object("my-bucket", "archives/lazy.bin"),
        Some(content)
    );
}

/// The writer goes to one task and the handle to another - which is the point of having
/// them separate. `finish` is awaited while the body is still being written.
#[tokio::test]
async fn the_writer_and_the_handle_live_on_different_tasks() {
    let server = FakeS3::start().await;
    let client = server.client();

    let content = pattern(2_000_000);
    let expected = content.clone();

    let (mut writer, handle) = client.start_upload(
        "my-bucket",
        "archives/two-tasks.bin",
        content.len(),
        UPLOAD_TIMEOUT,
    );

    let writing = tokio::spawn(async move {
        for piece in content.chunks(100_000) {
            writer.write_all(piece).await?;
        }
        writer.shutdown().await
    });

    let finishing = tokio::spawn(handle.finish());

    writing.await.unwrap().unwrap();
    finishing.await.unwrap().unwrap();

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/two-tasks.bin"),
        Some(expected)
    );
}

/// Two uploads at once, written alternately from one task. Each has its own channel and
/// its own connection, so neither waits on the other and neither's bytes end up in the
/// other's object.
///
/// Each object is far larger than what a writer can hold with its upload idle - the
/// queued chunks, the send waiting to join them, the buffer - so the alternating writes
/// can only get through if both requests drain their bodies at the same time. Two uploads
/// that ran one after the other would stall the loop, and the timeout would say so.
#[tokio::test]
async fn two_started_uploads_run_side_by_side() {
    let server = FakeS3::start().await;
    let client = server.client();

    let first = pattern(8 * 1024 * 1024);
    // A different period, so a chunk that went to the wrong object cannot compare equal.
    let second: Vec<u8> = (0..8 * 1024 * 1024 + 1_000)
        .map(|index| (index % 241) as u8)
        .collect();

    let (mut first_writer, first_handle) = client.start_upload(
        "my-bucket",
        "archives/first.bin",
        first.len(),
        UPLOAD_TIMEOUT,
    );
    let (mut second_writer, second_handle) = client.start_upload(
        "my-bucket",
        "archives/second.bin",
        second.len(),
        UPLOAD_TIMEOUT,
    );

    tokio::time::timeout(Duration::from_secs(30), async {
        let mut first_pieces = first.chunks(256 * 1024);
        let mut second_pieces = second.chunks(256 * 1024);

        loop {
            let first_piece = first_pieces.next();
            let second_piece = second_pieces.next();

            if first_piece.is_none() && second_piece.is_none() {
                break;
            }

            if let Some(piece) = first_piece {
                first_writer.write_all(piece).await.unwrap();
            }
            if let Some(piece) = second_piece {
                second_writer.write_all(piece).await.unwrap();
            }
        }
    })
    .await
    .expect("both uploads have to drain their bodies at the same time");

    // Two connections, and not one reused in turn. Waited for, because the server's
    // accept loop may lag behind a client that is already writing.
    tokio::time::timeout(Duration::from_secs(30), async {
        while server.connections_accepted() < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("each upload has to have a connection of its own");

    first_writer.shutdown().await.unwrap();
    second_writer.shutdown().await.unwrap();

    let (first_result, second_result) = tokio::join!(first_handle.finish(), second_handle.finish());
    first_result.unwrap();
    second_result.unwrap();

    assert_eq!(server.request_count(), 2);
    assert_eq!(
        server.uploaded_object("my-bucket", "archives/first.bin"),
        Some(first)
    );
    assert_eq!(
        server.uploaded_object("my-bucket", "archives/second.bin"),
        Some(second)
    );
}

/// The upload dies - here, its timeout runs out - while the writer is still alive and has
/// not tried to write since. The writer has not abandoned anything, so the answer is the
/// upload's own, retryable error; blaming the writer would turn the one case a caller
/// should retry into one it must not.
#[tokio::test]
async fn an_upload_that_dies_under_a_live_writer_reports_its_own_error() {
    let server = FakeS3::start().await;
    let client = server.client();

    let (mut writer, handle) = client.start_upload(
        "my-bucket",
        "archives/stalled.bin",
        32 * 1024 * 1024,
        Duration::from_secs(1),
    );

    writer
        .write_all(&pattern(2 * my_s3::DEFAULT_UPLOAD_CHUNK_SIZE))
        .await
        .unwrap();

    // The writer is still held, and owes 31 MiB.
    let err = tokio::time::timeout(Duration::from_secs(30), handle.finish())
        .await
        .expect("the upload's own timeout has to end the wait")
        .unwrap_err();

    assert!(
        !err.is_upload_producer_failed(),
        "a live writer cannot be what broke the upload - got: {}",
        err
    );
    assert!(err.is_retryable(), "a timeout is retryable - got: {}", err);

    let err = tokio::time::timeout(Duration::from_secs(30), write_until_refused(&mut writer))
        .await
        .expect("the writer has to find out");
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);

    assert_eq!(
        server.uploaded_object("my-bucket", "archives/stalled.bin"),
        None
    );
}

/// Both halves travel between tasks, and a handle may be held behind a shared reference
/// while something else is awaited.
#[test]
fn the_upload_handle_is_send_sync_and_unpin() {
    fn assert_send_sync_and_unpin<T: Send + Sync + Unpin>() {}

    assert_send_sync_and_unpin::<my_s3::S3UploadHandle>();
}

// ---------------------------------------------------------------------------
// Delete: the 204 bug
// ---------------------------------------------------------------------------

/// S3 answers a successful DeleteObject with 204 No Content. Accepting only 200 made
/// every delete return an error, and a hard delete silently removed nothing.
#[tokio::test]
async fn delete_succeeds_on_204_no_content() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(204, "");

    client.delete_file("my-bucket", "a/b.bin").await.unwrap();

    let captured = server.captured();
    assert_eq!(captured[0].method, "DELETE");
    assert_eq!(captured[0].target, "/my-bucket/a/b.bin");
    assert!(captured[0].signature_valid);
}

#[tokio::test]
async fn delete_reports_a_real_failure() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        403,
        "<Error><Code>AccessDenied</Code><Message>no</Message></Error>",
    );

    let err = client.delete_file("my-bucket", "a.bin").await.unwrap_err();

    assert_eq!(err.get_status_code(), Some(403));
}

// ---------------------------------------------------------------------------
// CopyObject
// ---------------------------------------------------------------------------

/// `SignedHeaders` out of the `Authorization` a request went out with.
fn signed_headers(captured: &fake_s3::Captured) -> &str {
    captured
        .header("authorization")
        .and_then(|authorization| authorization.split("SignedHeaders=").nth(1))
        .and_then(|rest| rest.split(',').next())
        .unwrap()
}

/// What a rename rests on: the object at the new key holds the very bytes of the old
/// one. They never pass through the client - the request carries no body at all.
#[tokio::test]
async fn a_copy_delivers_the_same_bytes() {
    let server = FakeS3::start().await;
    let client = server.client();

    let content = pattern(64 * 1024);
    server.put_object("my-bucket", "drafts/report.pdf", content.clone());

    client
        .copy_file(
            "my-bucket",
            "drafts/report.pdf",
            "my-bucket",
            "published/report.pdf",
        )
        .await
        .unwrap();

    let copied = client
        .download_file("my-bucket", "published/report.pdf")
        .await
        .unwrap();
    assert_eq!(read_to_end(copied).await, content);

    let captured = server.captured();
    assert_eq!(captured[0].method, "PUT");
    assert_eq!(captured[0].target, "/my-bucket/published/report.pdf");
    assert!(captured[0].body.is_empty());
    // A `PUT` without it is refused by S3 as 411 MissingContentLength.
    assert_eq!(captured[0].header("content-length"), Some("0"));
}

/// SigV4 signs every `x-amz-*` header, and S3 refuses a request carrying one it was not
/// signed with. A request with no header of its own is signed exactly as before.
#[tokio::test]
async fn the_copy_source_is_signed() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", b"a".to_vec());

    client
        .copy_file("my-bucket", "a.bin", "my-bucket", "b.bin")
        .await
        .unwrap();
    client.delete_file("my-bucket", "a.bin").await.unwrap();

    let captured = server.captured();

    assert_eq!(
        captured[0].header("x-amz-copy-source"),
        Some("/my-bucket/a.bin")
    );
    assert_eq!(
        signed_headers(&captured[0]),
        "host;x-amz-content-sha256;x-amz-copy-source;x-amz-date"
    );
    assert!(
        captured[0].signature_valid,
        "signature did not verify: {:?}",
        captured[0]
    );

    assert_eq!(captured[1].method, "DELETE");
    assert_eq!(
        signed_headers(&captured[1]),
        "host;x-amz-content-sha256;x-amz-date"
    );
    assert!(captured[1].signature_valid);
}

/// A `/` in the source key stays a `/`: percent-encoded, it would name one object
/// literally called `archives%2F2024...`.
#[tokio::test]
async fn a_copy_source_key_with_slashes_stays_a_path() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "archives/2024/06/backup.tar", b"tar".to_vec());

    client
        .copy_file(
            "my-bucket",
            "archives/2024/06/backup.tar",
            "my-bucket",
            "archives/2024/07/backup.tar",
        )
        .await
        .unwrap();

    let captured = server.captured();
    assert_eq!(
        captured[0].header("x-amz-copy-source"),
        Some("/my-bucket/archives/2024/06/backup.tar")
    );
    assert_eq!(captured[0].target, "/my-bucket/archives/2024/07/backup.tar");
    assert!(captured[0].signature_valid);

    let copied = client
        .download_file("my-bucket", "archives/2024/07/backup.tar")
        .await
        .unwrap();
    assert_eq!(read_to_end(copied).await, b"tar");
}

/// A key that has to be percent-encoded goes into the copy source exactly as into the
/// path of a request for it - including what `fl-url` leaves as it is, `+` and `(`. The
/// two must name the same object: a rename deletes by the path what it copied by this
/// header.
#[tokio::test]
async fn a_copy_source_key_is_encoded_as_its_request_path() {
    let server = FakeS3::start().await;
    let client = server.client();

    let key = "отчёты/2024 q1/a+b (1) 100%?#.txt";
    server.put_object("my-bucket", key, b"report".to_vec());

    // The path a request for the source goes out with.
    let source = client.download_file("my-bucket", key).await.unwrap();
    assert_eq!(read_to_end(source).await, b"report");

    client
        .copy_file("my-bucket", key, "my-bucket", "archive/report.txt")
        .await
        .unwrap();

    let captured = server.captured();
    let copy_source = captured[1].header("x-amz-copy-source").unwrap();

    assert_eq!(
        copy_source,
        "/my-bucket/%D0%BE%D1%82%D1%87%D1%91%D1%82%D1%8B/2024%20q1/a+b%20(1)%20100%25%3F%23.txt"
    );
    assert_eq!(copy_source, captured[0].target);
    assert!(captured[1].signature_valid);

    let copied = client
        .download_file("my-bucket", "archive/report.txt")
        .await
        .unwrap();
    assert_eq!(read_to_end(copied).await, b"report");
}

/// CopyObject may answer `200 OK` before it has copied anything, so an error it meets on
/// the way can only come back inside that 200 - and it is an error, not a copy.
#[tokio::test]
async fn an_error_inside_a_200_is_not_a_copy() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        200,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>InternalError</Code><Message>We encountered an internal error. Please try again.</Message></Error>",
    );

    let err = client
        .copy_file("my-bucket", "a.bin", "my-bucket", "b.bin")
        .await
        .unwrap_err();

    match &err {
        my_s3::S3Error::UnexpectedStatusCode {
            status_code,
            error_code,
            ..
        } => {
            assert_eq!(*status_code, 200);
            assert_eq!(error_code.as_deref(), Some("InternalError"));
        }
        _ => panic!("expected UnexpectedStatusCode, got {:?}", err),
    }

    // Whether to repeat it is the caller's call, and this is what it is made on.
    assert!(err.is_retryable());
}

/// A source that is not there is the typed "no such key" - the answer a `GET` for it
/// gets - and nothing appears at the destination.
#[tokio::test]
async fn copying_a_missing_source_is_key_not_found() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "other.bin", b"x".to_vec());

    let err = client
        .copy_file("my-bucket", "gone.bin", "my-bucket", "b.bin")
        .await
        .unwrap_err();

    assert!(err.is_key_not_found(), "got {:?}", err);
    assert!(!err.is_retryable());

    let err = client
        .download_file("my-bucket", "b.bin")
        .await
        .unwrap_err();
    assert!(err.is_key_not_found(), "the destination must not exist");
}

/// An empty key names no object: the `PUT` would go to the bucket itself, which creates
/// buckets. It is refused before anything is sent.
#[tokio::test]
async fn an_empty_name_is_refused_without_a_request() {
    let server = FakeS3::start().await;
    let client = server.client();

    let err = client
        .copy_file("my-bucket", "a.bin", "my-bucket", "")
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("the destination key is empty"),
        "got {}",
        err
    );

    let err = client
        .copy_file("", "a.bin", "my-bucket", "b.bin")
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("the source bucket is empty"),
        "got {}",
        err
    );
    assert!(!err.is_retryable());

    assert_eq!(server.connections_accepted(), 0);
}

// ---------------------------------------------------------------------------
// Typed errors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_missing_key_is_typed_not_a_string() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(404, no_such_key_xml());

    let err = client
        .download_file("my-bucket", "gone.bin")
        .await
        .unwrap_err();

    assert!(err.is_key_not_found());
    assert!(!err.is_retryable());
}

/// Re-creating a bucket we already own is the state on every restart, and it arrives as
/// 409 - the same status as `BucketAlreadyExists`, so only the body distinguishes them.
#[tokio::test]
async fn recreating_our_own_bucket_is_typed() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        409,
        "<Error><Code>BucketAlreadyOwnedByYou</Code><Message>you own it</Message></Error>",
    );

    let err = client.create_bucket("my-bucket").await.unwrap_err();

    assert!(err.is_bucket_already_owned_by_you());
    assert!(err.bucket_name_is_taken());
    assert!(!err.is_bucket_already_exists());

    let captured = server.captured();
    assert_eq!(captured[0].target, "/my-bucket");
    assert!(captured[0].signature_valid);
}

#[tokio::test]
async fn a_bucket_taken_by_somebody_else_stays_distinct() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        409,
        "<Error><Code>BucketAlreadyExists</Code><Message>taken</Message></Error>",
    );

    let err = client.create_bucket("my-bucket").await.unwrap_err();

    assert!(err.is_bucket_already_exists());
    assert!(!err.is_bucket_already_owned_by_you());
    assert!(err.bucket_name_is_taken());
}

#[tokio::test]
async fn create_bucket_succeeds_on_200() {
    let server = FakeS3::start().await;
    let client = server.client();

    client.create_bucket("my-bucket").await.unwrap();

    assert_eq!(server.captured()[0].method, "PUT");
}

// ---------------------------------------------------------------------------
// CreateBucket: the location constraint
// ---------------------------------------------------------------------------

fn location_constraint_xml(region: &str) -> String {
    format!(
        "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>{}</LocationConstraint></CreateBucketConfiguration>",
        region
    )
}

/// `CreateBucket` names its region twice - the endpoint and the body - and S3 requires
/// the two to agree. An empty body is not "any region", it is literally `us-east-1`, so
/// against every other regional endpoint it used to answer
/// `400 IllegalLocationConstraintException` and no bucket was ever created outside
/// `us-east-1`.
#[tokio::test]
async fn create_bucket_outside_us_east_1_states_the_location() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-west-1");

    client.create_bucket("my-bucket").await.unwrap();

    let captured = server.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].method, "PUT");
    assert_eq!(captured[0].target, "/my-bucket");
    assert_eq!(
        String::from_utf8_lossy(&captured[0].body),
        location_constraint_xml("eu-west-1")
    );
}

/// The body is covered by the signature, so the bytes handed to the signer have to be
/// the bytes that go out. Signing an empty payload and then sending the XML turns the
/// 400 into a 403 SignatureDoesNotMatch - a different bug wearing the same shirt.
#[tokio::test]
async fn the_location_constraint_is_covered_by_the_signature() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-central-1");

    client.create_bucket("my-bucket").await.unwrap();

    let captured = server.captured();

    // `signature_valid` already refuses a payload hash that does not match the body;
    // this pins the header itself, so a regression cannot hide behind the verifier.
    assert_eq!(
        captured[0].header("x-amz-content-sha256"),
        Some(hex::encode(sha2::Sha256::digest(&captured[0].body)).as_str())
    );
    assert!(
        captured[0].signature_valid,
        "the signature must cover the body as sent: {:?}",
        captured[0]
    );
}

/// The one region that must **not** be named: AWS rejects an explicit
/// `LocationConstraint` of `us-east-1`, so there the empty body is the correct request
/// and the payload hash stays the canonical hash of nothing.
#[tokio::test]
async fn create_bucket_in_us_east_1_sends_no_body() {
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    let server = FakeS3::start().await;
    let client = server.client_in_region("us-east-1");

    client.create_bucket("my-bucket").await.unwrap();

    let captured = server.captured();
    assert!(
        captured[0].body.is_empty(),
        "AWS rejects an explicit us-east-1 LocationConstraint, got {:?}",
        String::from_utf8_lossy(&captured[0].body)
    );
    assert_eq!(
        captured[0].header("x-amz-content-sha256"),
        Some(EMPTY_SHA256)
    );
    assert!(captured[0].signature_valid);
}

/// Only `create_bucket` carries a body: adding one to a verb that never had one would
/// break every other call's signature, and this is the assertion that would catch it.
#[tokio::test]
async fn no_other_request_grew_a_body() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-west-1");

    server.push_reply(200, "contents");
    let stream = client.download_file("my-bucket", "a.bin").await.unwrap();
    read_to_end(stream).await;

    server.push_reply(204, "");
    client.delete_file("my-bucket", "a.bin").await.unwrap();

    for captured in server.captured() {
        assert!(
            captured.body.is_empty(),
            "{} must not carry a body: {:?}",
            captured.method,
            captured
        );
        assert!(captured.signature_valid);
    }
}

// ---------------------------------------------------------------------------
// GetBucketLocation
// ---------------------------------------------------------------------------

fn location_answer(region: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{}</LocationConstraint>",
        region
    )
}

/// `?location` is a valueless flag and it is part of the canonical request, so it has
/// to be appended *before* signing - SigV4 canonicalises it to `location=`. Getting
/// that wrong is a 403 that looks like bad credentials.
#[tokio::test]
async fn get_bucket_location_asks_for_the_location_subresource() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-west-1");

    server.push_reply(200, location_answer("eu-west-1").as_str());

    let region = client.get_bucket_location("my-bucket").await.unwrap();

    assert_eq!(region, my_s3::S3Region::AwsEuWest1);

    let captured = server.captured();
    assert_eq!(captured[0].method, "GET");
    assert_eq!(captured[0].target, "/my-bucket?location");
    assert!(
        captured[0].signature_valid,
        "the query param must be covered by the signature: {:?}",
        captured[0]
    );
}

/// The answer is the storage's own, and it does not have to agree with what this client
/// was configured for - that disagreement is the whole reason to ask.
#[tokio::test]
async fn get_bucket_location_reports_a_region_other_than_the_configured_one() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-west-1");

    server.push_reply(200, location_answer("fsn1").as_str());

    assert_eq!(
        client.get_bucket_location("my-bucket").await.unwrap(),
        my_s3::S3Region::HetznerFsn1
    );
}

/// AWS states `us-east-1` by sending an empty constraint - the same asymmetry
/// `CreateBucket` has from the other side.
#[tokio::test]
async fn get_bucket_location_reads_an_empty_constraint_as_us_east_1() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("us-east-1");

    server.push_reply(
        200,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>",
    );

    assert_eq!(
        client.get_bucket_location("my-bucket").await.unwrap(),
        my_s3::S3Region::AwsUsEast1
    );
}

#[tokio::test]
async fn get_bucket_location_on_a_missing_bucket_is_typed() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        404,
        "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist.</Message></Error>",
    );

    let err = client.get_bucket_location("my-bucket").await.unwrap_err();

    assert!(err.is_bucket_not_found());
}

// ---------------------------------------------------------------------------
// CheckIfBucketExists
// ---------------------------------------------------------------------------

/// A HEAD carries no body, in the request or in the answer, so the status code is the
/// entire result.
#[tokio::test]
async fn a_bucket_that_is_there_is_reported_as_existing() {
    let server = FakeS3::start().await;
    let client = server.client();

    assert!(client.check_if_bucket_exists("my-bucket").await.unwrap());

    let captured = server.captured();
    assert_eq!(captured[0].method, "HEAD");
    assert_eq!(captured[0].target, "/my-bucket");
    assert!(captured[0].body.is_empty());
    assert!(captured[0].signature_valid);
}

/// "Not there" is an answer, not a failure: `Ok(false)`, so the caller does not have to
/// pattern-match an error to learn something ordinary.
#[tokio::test]
async fn a_missing_bucket_is_reported_as_absent_not_as_an_error() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(404, "");

    assert!(!client.check_if_bucket_exists("my-bucket").await.unwrap());
}

/// A 403 must not collapse into "it exists": it means the name belongs to another
/// account *or* that these credentials are wrong, and the second one has to be visible.
#[tokio::test]
async fn a_forbidden_bucket_stays_an_error() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(403, "");

    let err = client
        .check_if_bucket_exists("my-bucket")
        .await
        .unwrap_err();

    assert_eq!(err.get_status_code(), Some(403));
    assert!(!err.is_retryable());
}

/// A HEAD followed by an ordinary request on the same client, end to end - the sequence
/// a caller makes when it checks for the bucket and then uses it.
///
/// Note this does not prove anything about connection pooling: the client survives a
/// server that wrongly writes a body after HEAD headers too, so the assertion here is
/// only that both calls complete and both are seen.
#[tokio::test]
async fn a_head_is_followed_by_a_working_request() {
    let server = FakeS3::start().await;
    let client = server.client();

    assert!(client.check_if_bucket_exists("my-bucket").await.unwrap());

    server.push_reply(200, "file contents");
    let stream = client.download_file("my-bucket", "a.bin").await.unwrap();

    assert_eq!(read_to_end(stream).await, b"file contents");
    assert_eq!(server.request_count(), 2);
}

// ---------------------------------------------------------------------------
// Debug mode
// ---------------------------------------------------------------------------

/// Tracing must be a pure observation: the same bytes go out, and the signature still
/// verifies. Routing a request through `FlUrl`'s `*_with_debug` variants is the kind of
/// change that could quietly compile the request differently.
#[tokio::test]
async fn debug_mode_does_not_change_what_goes_on_the_wire() {
    let server = FakeS3::start().await;

    let quiet = server.client_in_region("eu-west-1");
    quiet.create_bucket("my-bucket").await.unwrap();

    let loud = server.client_in_region("eu-west-1").debug_to_console();
    loud.create_bucket("my-bucket").await.unwrap();

    let captured = server.captured();
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0].body, captured[1].body);
    assert_eq!(captured[0].target, captured[1].target);
    assert!(
        captured[1].signature_valid,
        "debug mode must not disturb the signature: {:?}",
        captured[1]
    );
}

/// Every verb has its own `FlUrl` debug entry point, including the streamed one, so
/// each path is exercised - a missing one would show up as a compile error at best and
/// a silently untraced request at worst.
#[tokio::test]
async fn every_verb_survives_debug_mode() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-west-1").debug_to_console();

    client.create_bucket("my-bucket").await.unwrap();

    client
        .upload("my-bucket", "a.bin", b"hello".to_vec(), UPLOAD_TIMEOUT)
        .await
        .unwrap();

    client
        .upload_streamed(
            "my-bucket",
            "b.bin",
            body_from(b"streamed".to_vec(), 4),
            8,
            UPLOAD_TIMEOUT,
        )
        .await
        .unwrap();

    server.push_reply(200, "contents");
    let stream = client.download_file("my-bucket", "a.bin").await.unwrap();
    read_to_end(stream).await;

    server.push_reply(204, "");
    client.delete_file("my-bucket", "a.bin").await.unwrap();

    client.check_if_bucket_exists("my-bucket").await.unwrap();

    server.push_reply(200, location_answer("eu-west-1").as_str());
    client.get_bucket_location("my-bucket").await.unwrap();

    assert_eq!(server.request_count(), 7);
    for captured in server.captured() {
        assert!(
            captured.signature_valid,
            "{} {} lost its signature under debug mode",
            captured.method, captured.target
        );
    }
}

/// The failure path is the one debug mode is turned on for, so it has to survive it -
/// and still come back typed rather than as a printed message.
#[tokio::test]
async fn a_failure_under_debug_mode_is_still_typed() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-west-1").debug_to_console();

    server.push_reply(
        400,
        "<Error><Code>IllegalLocationConstraintException</Code><Message>The unspecified location constraint is incompatible for the region specific endpoint this request was sent to.</Message></Error>",
    );

    let err = client.create_bucket("my-bucket").await.unwrap_err();

    assert_eq!(err.get_status_code(), Some(400));
    assert!(!err.is_retryable());
}

// ---------------------------------------------------------------------------
// CreateBucket: creating one that is already there
// ---------------------------------------------------------------------------

/// Creating the bucket before using it is the normal way to ensure it exists, so the
/// call has to survive being made again against a bucket that is already ours - S3
/// answers that with 409 `BucketAlreadyOwnedByYou`.
#[tokio::test]
async fn creating_a_bucket_that_is_already_ours_is_tolerated() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-west-1");

    // First call: the bucket gets created.
    client
        .create_bucket_if_not_exists("my-bucket")
        .await
        .unwrap();

    // Every call after that: S3 says it is already there and it is ours.
    server.push_reply(
        409,
        "<Error><Code>BucketAlreadyOwnedByYou</Code><Message>you own it</Message></Error>",
    );

    client
        .create_bucket_if_not_exists("my-bucket")
        .await
        .unwrap();

    let captured = server.captured();
    assert_eq!(captured.len(), 2);

    // The repeat is the same well-formed, correctly signed request as the first one -
    // it is answered differently, not sent differently.
    for attempt in &captured {
        assert_eq!(
            String::from_utf8_lossy(&attempt.body),
            location_constraint_xml("eu-west-1")
        );
        assert!(attempt.signature_valid);
    }
}

/// The tolerance stops exactly where the bucket stops being ours: a name held by
/// another account means the bucket that exists is not the one about to be written to.
#[tokio::test]
async fn a_bucket_owned_by_somebody_else_is_not_tolerated() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-west-1");

    server.push_reply(
        409,
        "<Error><Code>BucketAlreadyExists</Code><Message>taken</Message></Error>",
    );

    let err = client
        .create_bucket_if_not_exists("my-bucket")
        .await
        .unwrap_err();

    assert!(err.is_bucket_already_exists());
    assert!(!err.is_bucket_already_owned_by_you());
}

/// A real failure is not swallowed either - only the "already ours" answer is.
#[tokio::test]
async fn create_bucket_if_not_exists_still_reports_a_real_failure() {
    let server = FakeS3::start().await;
    let client = server.client_in_region("eu-west-1");

    server.push_reply(
        403,
        "<Error><Code>AccessDenied</Code><Message>no</Message></Error>",
    );

    let err = client
        .create_bucket_if_not_exists("my-bucket")
        .await
        .unwrap_err();

    assert_eq!(err.get_status_code(), Some(403));
}

// ---------------------------------------------------------------------------
// Download, including ranges
// ---------------------------------------------------------------------------

#[tokio::test]
async fn download_returns_the_body() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, "file contents");

    let stream = client.download_file("my-bucket", "a.bin").await.unwrap();

    assert_eq!(read_to_end(stream).await, b"file contents");
    assert_eq!(server.captured()[0].method, "GET");
}

/// `download_file` is asked for the whole object, so it delivers one of any size: this
/// crate puts no limit on it. 11 MB is past the 10 MB a buffered read of FlUrl used to
/// be refused at by default.
#[tokio::test]
async fn download_reads_an_object_of_any_size() {
    let server = FakeS3::start().await;
    let client = server.client();

    let content = pattern(11 * 1024 * 1024);
    server.put_object("my-bucket", "big.bin", content.clone());

    let stream = client.download_file("my-bucket", "big.bin").await.unwrap();
    let body = read_to_end(stream).await;

    assert!(body == content, "got {} bytes", body.len());
}

/// `Range` is not in SignedHeaders, so it is added after signing - this checks that
/// doing so does not invalidate the signature.
#[tokio::test]
async fn a_range_request_is_still_correctly_signed() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(206, "artial");

    let stream = client
        .download_file_range("my-bucket", "a.bin", 1, Some(6))
        .await
        .unwrap();

    assert_eq!(read_to_end(stream).await, b"artial");

    let captured = server.captured();
    assert_eq!(captured[0].header("range"), Some("bytes=1-6"));
    assert!(captured[0].signature_valid);
}

/// A range is handed over as a stream - returned once the head has arrived, with the
/// range's own length - so a large one is never held unless the caller chooses to.
#[tokio::test]
async fn a_range_is_handed_over_as_a_stream() {
    let server = FakeS3::start().await;
    let client = server.client();

    let content = pattern(3 * 1024 * 1024);
    server.put_object("my-bucket", "big.bin", content.clone());

    let mut stream = client
        .download_file_range("my-bucket", "big.bin", 1024, Some(2 * 1024 * 1024 - 1))
        .await
        .unwrap();

    assert_eq!(stream.content_length, Some(2 * 1024 * 1024 - 1024));

    let mut body = Vec::new();
    while let Some(chunk) = stream.get_next_chunk().await.unwrap() {
        body.extend_from_slice(&chunk);
    }

    assert!(
        body.as_slice() == &content[1024..2 * 1024 * 1024],
        "got {} bytes",
        body.len()
    );
    assert_eq!(stream.received(), body.len() as u64);
}

#[tokio::test]
async fn an_open_ended_range_is_sent_without_an_upper_bound() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(206, "tail");

    client
        .download_file_range("my-bucket", "a.bin", 10, None)
        .await
        .unwrap();

    assert_eq!(server.captured()[0].header("range"), Some("bytes=10-"));
}

#[tokio::test]
async fn a_range_past_the_end_is_typed() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        416,
        "<Error><Code>InvalidRange</Code><Message>nope</Message></Error>",
    );

    let err = client
        .download_file_range("my-bucket", "a.bin", 9_000, None)
        .await
        .unwrap_err();

    assert!(err.is_range_not_satisfiable());
}

/// If the server ignores `Range` and returns the whole object, silently handing back
/// far more data than asked for would be worse than failing.
#[tokio::test]
async fn a_range_answered_with_200_is_reported() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, "the entire object");

    let err = client
        .download_file_range("my-bucket", "a.bin", 1, Some(3))
        .await
        .unwrap_err();

    assert!(!err.is_range_not_satisfiable());
    assert!(err.to_string().contains("ignored the Range header"));
}

#[tokio::test]
async fn an_inverted_range_is_rejected_before_any_request() {
    let server = FakeS3::start().await;
    let client = server.client();

    let err = client
        .download_file_range("my-bucket", "a.bin", 10, Some(5))
        .await
        .unwrap_err();

    assert!(err.to_string().contains("Invalid range"));
    assert_eq!(server.request_count(), 0, "must not hit the network");
}

// ---------------------------------------------------------------------------
// ListObjectsV2
// ---------------------------------------------------------------------------

fn listing_xml() -> &'static str {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>my-bucket</Name>
  <Prefix>photos/</Prefix>
  <Delimiter>/</Delimiter>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>photos/cover.jpg</Key>
    <LastModified>2024-07-01T12:34:56.000Z</LastModified>
    <ETag>&quot;abc&quot;</ETag>
    <Size>1048576</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <CommonPrefixes><Prefix>photos/2024/</Prefix></CommonPrefixes>
</ListBucketResult>"#
}

/// The plainest possible listing: the sub-resource and nothing else.
#[tokio::test]
async fn list_objects_asks_for_list_type_2_and_nothing_more() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, listing_xml());

    client
        .list_objects_v2("my-bucket", my_s3::S3ListObjectsRequest::default())
        .await
        .unwrap();

    let captured = &server.captured()[0];

    assert_eq!(captured.method, "GET");
    // No trailing slash on the bucket: `/my-bucket`, not `/my-bucket/`.
    assert_eq!(captured.target, "/my-bucket?list-type=2");
    assert!(captured.signature_valid);
    assert!(captured.body.is_empty());
}

/// A parameter that was not asked for must not appear at all - `delimiter=` is a
/// different request from no delimiter, and would flatten a listing that wanted folders.
#[tokio::test]
async fn parameters_that_were_not_asked_for_are_not_sent() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, listing_xml());

    client
        .list_objects_v2(
            "my-bucket",
            my_s3::S3ListObjectsRequest {
                delimiter: Some("/"),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let target = &server.captured()[0].target;

    assert_eq!(target, "/my-bucket?list-type=2&delimiter=%2F");
    assert!(!target.contains("prefix"));
    assert!(!target.contains("continuation-token"));
    assert!(!target.contains("max-keys"));
}

/// **The signing case.** A folder prefix carries `/`, and this one also carries a space.
/// `FlUrl`'s own query encoder would send `photos%2F2024+summer%2F`: S3 would read the
/// `+` as a plus rather than a space and answer with an empty listing, and its own
/// canonical query would say `%20` where ours said `+`, so the request would be refused
/// as `SignatureDoesNotMatch` first.
#[tokio::test]
async fn a_prefix_with_a_slash_and_a_space_is_uri_encoded_not_form_encoded() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, listing_xml());

    client
        .list_objects_v2(
            "my-bucket",
            my_s3::S3ListObjectsRequest {
                prefix: Some("photos/2024 summer/"),
                delimiter: Some("/"),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let captured = &server.captured()[0];

    assert_eq!(
        captured.target,
        "/my-bucket?list-type=2&prefix=photos%2F2024%20summer%2F&delimiter=%2F"
    );
    assert!(
        !captured.target.contains('+'),
        "a space must be %20, never +: {}",
        captured.target
    );
    assert!(captured.signature_valid);
}

/// A continuation token is base64, so it carries `+`, `/` and `=` - the three characters
/// that would otherwise end the parameter early or turn into a different token.
#[tokio::test]
async fn a_continuation_token_reaches_the_wire_intact() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, listing_xml());

    client
        .list_objects_v2(
            "my-bucket",
            my_s3::S3ListObjectsRequest {
                continuation_token: Some("1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM="),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let captured = &server.captured()[0];

    assert_eq!(
        captured.target,
        "/my-bucket?list-type=2&continuation-token=1ueGcxLPRx1Tr%2FXYExHnhbYLgveDs2J%2Fwm36Hy4vbOwM%3D"
    );
    assert!(captured.signature_valid);
}

/// A non-ASCII prefix has to be encoded over its UTF-8 bytes, because that is what the
/// server re-encodes when it rebuilds the canonical query.
#[tokio::test]
async fn a_non_ascii_prefix_is_signed_as_its_utf8_bytes() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, listing_xml());

    client
        .list_objects_v2(
            "my-bucket",
            my_s3::S3ListObjectsRequest {
                prefix: Some("документы/"),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let captured = &server.captured()[0];

    assert_eq!(
        captured.target,
        "/my-bucket?list-type=2&prefix=%D0%B4%D0%BE%D0%BA%D1%83%D0%BC%D0%B5%D0%BD%D1%82%D1%8B%2F"
    );
    assert!(captured.signature_valid);
}

#[tokio::test]
async fn max_keys_is_sent_as_a_number() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, listing_xml());

    client
        .list_objects_v2(
            "my-bucket",
            my_s3::S3ListObjectsRequest {
                max_keys: Some(37),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(
        server.captured()[0].target,
        "/my-bucket?list-type=2&max-keys=37"
    );
}

/// End to end: the answer a real storage sends, read into the shape a caller uses.
#[tokio::test]
async fn list_objects_reads_the_page_the_storage_answered_with() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, listing_xml());

    let page = client
        .list_objects_v2(
            "my-bucket",
            my_s3::S3ListObjectsRequest {
                prefix: Some("photos/"),
                delimiter: Some("/"),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(page.common_prefixes, ["photos/2024/"]);
    assert_eq!(page.objects.len(), 1);
    assert_eq!(page.objects[0].key, "photos/cover.jpg");
    assert_eq!(page.objects[0].size, 1_048_576);
    assert_eq!(page.next_continuation_token, None);
}

/// Walking the whole listing is a loop over the token, and the second request has to
/// carry the first one's token *and* repeat the prefix and delimiter unchanged.
#[tokio::test]
async fn a_truncated_listing_is_resumed_with_the_token_it_handed_back() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        200,
        r#"<ListBucketResult>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>page/2=</NextContinuationToken>
  <Contents><Key>photos/a.jpg</Key><LastModified>x</LastModified><Size>1</Size></Contents>
</ListBucketResult>"#,
    );
    server.push_reply(
        200,
        r#"<ListBucketResult>
  <IsTruncated>false</IsTruncated>
  <Contents><Key>photos/b.jpg</Key><LastModified>x</LastModified><Size>2</Size></Contents>
</ListBucketResult>"#,
    );

    let mut keys = Vec::new();
    let mut token = None;

    loop {
        let page = client
            .list_objects_v2(
                "my-bucket",
                my_s3::S3ListObjectsRequest {
                    prefix: Some("photos/"),
                    delimiter: Some("/"),
                    continuation_token: token.as_deref(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        keys.extend(page.objects.into_iter().map(|object| object.key));

        token = page.next_continuation_token;
        if token.is_none() {
            break;
        }
    }

    assert_eq!(keys, ["photos/a.jpg", "photos/b.jpg"]);

    let captured = server.captured();
    assert_eq!(captured.len(), 2);
    assert!(!captured[0].target.contains("continuation-token"));
    assert_eq!(
        captured[1].target,
        "/my-bucket?list-type=2&prefix=photos%2F&delimiter=%2F&continuation-token=page%2F2%3D"
    );
    assert!(captured[1].signature_valid);
}

#[tokio::test]
async fn listing_a_missing_bucket_is_typed() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(
        404,
        "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist.</Message></Error>",
    );

    let err = client
        .list_objects_v2("my-bucket", my_s3::S3ListObjectsRequest::default())
        .await
        .unwrap_err();

    assert!(err.is_bucket_not_found());
}

/// A 200 whose body is not a listing at all - a proxy's page, say - must not read as an
/// empty bucket. "There is nothing here" and "I could not tell" are different answers.
#[tokio::test]
async fn a_success_that_is_not_a_listing_is_not_an_empty_bucket() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, "<html><body>Service Unavailable</body></html>");

    assert!(
        client
            .list_objects_v2("my-bucket", my_s3::S3ListObjectsRequest::default())
            .await
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// Streamed download
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_streamed_download_delivers_the_whole_object() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, "the whole object, one chunk or several");

    let mut stream = client.download_file("my-bucket", "a.bin").await.unwrap();

    let mut body = Vec::new();
    while let Some(chunk) = stream.get_next_chunk().await.unwrap() {
        body.extend_from_slice(&chunk);
    }

    assert_eq!(body, b"the whole object, one chunk or several");
    assert_eq!(stream.received(), body.len() as u64);

    let captured = &server.captured()[0];
    assert_eq!(captured.method, "GET");
    assert_eq!(captured.target, "/my-bucket/a.bin");
    assert!(captured.signature_valid);
}

/// Both are what forwarding the object over HTTP needs, and both have to be read off the
/// response before the body is taken - the response is consumed by that.
#[tokio::test]
async fn a_streamed_download_carries_the_length_and_the_type() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(200, "0123456789");

    let stream = client.download_file("my-bucket", "a.bin").await.unwrap();

    assert_eq!(stream.content_length, Some(10));
    assert_eq!(stream.content_type.as_deref(), Some("application/xml"));
}

/// A failure is still typed: the body of a non-2xx answer is the `<Error><Code>`, it is
/// small, and it is read rather than streamed.
#[tokio::test]
async fn a_streamed_download_of_a_missing_key_is_typed() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(404, no_such_key_xml());

    let err = client
        .download_file("my-bucket", "missing.bin")
        .await
        .unwrap_err();

    assert!(err.is_key_not_found());
}

/// **The one that matters for a file that gets written out.** The storage announced 64
/// bytes, sent 9, and hung up. Reporting the end of the stream here would hand back a
/// truncated file and call it a success.
#[tokio::test]
async fn a_body_that_ends_early_is_an_error_not_a_short_file() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_truncated_reply("truncated", 64);

    let mut stream = client.download_file("my-bucket", "a.bin").await.unwrap();

    assert_eq!(stream.content_length, Some(64));

    let mut received = Vec::new();
    let outcome = loop {
        match stream.get_next_chunk().await {
            Ok(Some(chunk)) => received.extend_from_slice(&chunk),
            Ok(None) => break Ok(()),
            Err(err) => break Err(err),
        }
    };

    // Which of the two guards fires is an implementation detail - the transport
    // notices a body that stopped before `Content-Length` and reports a read error,
    // and the byte count in `S3DownloadStream` is the backstop behind it. What must
    // never happen is `Ok(None)`: that is the answer that writes out half a file and
    // calls it a success.
    let err = outcome.expect_err("a body that stopped short must not read as the end of one");

    assert!(received.len() < 64, "got {} bytes", received.len());
    // A cut connection is worth retrying; a 404 is not. The distinction has to survive.
    assert!(err.is_retryable(), "{}", err);
}

/// A streamed download under tracing goes out as the same request - the trace must not
/// reach for the body, which is the one thing it may not read here.
#[tokio::test]
async fn a_streamed_download_survives_debug_mode() {
    let server = FakeS3::start().await;
    let client = server.client().debug_to_console();

    server.push_reply(200, "contents");

    let mut stream = client.download_file("my-bucket", "a.bin").await.unwrap();

    let mut body = Vec::new();
    while let Some(chunk) = stream.get_next_chunk().await.unwrap() {
        body.extend_from_slice(&chunk);
    }

    assert_eq!(body, b"contents");
    assert!(server.captured()[0].signature_valid);
}

// ---------------------------------------------------------------------------
// The harness itself
// ---------------------------------------------------------------------------

/// A test server that agrees with the client is worth nothing. This pins the one thing
/// `FakeS3` has to get *independently* right: a real S3 rebuilds the canonical query by
/// decoding and re-encoding it under RFC 3986, so a client that encoded its query the
/// `x-www-form-urlencoded` way signs a different string from the one the server signs.
///
/// Without this, `fake_s3` took the query off the wire verbatim and would have called a
/// `+`-for-space request correctly signed - the exact bug the client's encoder exists to
/// avoid, validated by a server that shared it.
#[test]
fn the_fake_server_canonicalises_a_query_the_way_a_real_one_does() {
    // A space sent as `+` is not the same canonical string as a space sent as `%20`,
    // which is what makes the wrong encoding a 403 rather than a silent success.
    assert_ne!(
        fake_s3::canonical_query("prefix=a+b"),
        fake_s3::canonical_query("prefix=a%20b")
    );
    assert_eq!(fake_s3::canonical_query("prefix=a+b"), "prefix=a%2Bb");
    assert_eq!(fake_s3::canonical_query("prefix=a%20b"), "prefix=a%20b");

    // `!` is not unreserved, so a client that left it literal signs a different string.
    assert_eq!(fake_s3::canonical_query("k=a!b"), "k=a%21b");
    // `~` is unreserved and must stay literal on both sides.
    assert_eq!(fake_s3::canonical_query("k=a~b"), "k=a~b");

    // Ordering is by encoded name, then encoded value; a valueless flag gets its `=`.
    assert_eq!(fake_s3::canonical_query("b=2&a=1"), "a=1&b=2");
    assert_eq!(fake_s3::canonical_query("location"), "location=");
    assert_eq!(fake_s3::canonical_query(""), "");

    // Re-encoding has to be idempotent for a correctly encoded query, or every one of
    // our requests would fail.
    let ours = "continuation-token=1ueGcxLPRx1Tr%2FXYExHnhbYLgveDs2J%2Fwm36Hy4vbOwM%3D\
&delimiter=%2F&list-type=2&prefix=photos%2F2024%20summer%2F";
    assert_eq!(fake_s3::canonical_query(ours), ours);
}

/// "The copy source is signed" is only worth asserting against a server that checks it
/// the way S3 does: an `x-amz-*` header missing from `SignedHeaders` is a refusal,
/// however well the rest of the request was signed. Otherwise a copy that forgot to
/// sign it would pass here and fail against the storage.
#[tokio::test]
async fn the_fake_server_refuses_an_unsigned_amz_header() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(204, "");
    client.delete_file("my-bucket", "a.bin").await.unwrap();

    let request = server.captured().remove(0);
    assert!(fake_s3::verify_signature(
        &request.method,
        &request.target,
        &request.headers,
        &request.body
    ));

    let mut headers = request.headers.clone();
    headers.push((
        "x-amz-copy-source".to_string(),
        "/my-bucket/b.bin".to_string(),
    ));

    assert!(!fake_s3::verify_signature(
        &request.method,
        &request.target,
        &headers,
        &request.body
    ));
}

// ---------------------------------------------------------------------------
// S3Reader - one object as a seekable source
// ---------------------------------------------------------------------------

/// A pattern rather than a constant byte, so that a slice taken at the wrong offset is
/// visibly the wrong slice. 251 is prime, so the period never lines up with a
/// power-of-two page size.
fn object_of(size: usize) -> Vec<u8> {
    (0..size).map(|index| (index % 251) as u8).collect()
}

/// Opening reports the size and costs exactly one request - the `HEAD`.
#[tokio::test]
async fn opening_a_reader_costs_one_head() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(4096));

    let reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    assert_eq!(reader.size(), 4096);
    assert_eq!(reader.position(), 0);

    let captured = server.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].method, "HEAD");
    assert_eq!(captured[0].target, "/my-bucket/a.bin");
    assert!(captured[0].signature_valid);
}

/// `HEAD` on its own, without a reader.
#[tokio::test]
async fn get_object_size_reads_content_length() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(12_345));

    assert_eq!(
        client.get_object_size("my-bucket", "a.bin").await.unwrap(),
        12_345
    );
    assert_eq!(server.captured()[0].method, "HEAD");
}

/// The point of the whole type: seek to an offset, read a page, get *those* bytes.
#[tokio::test]
async fn seek_then_read_exact_returns_the_bytes_at_that_offset() {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let server = FakeS3::start().await;
    let client = server.client();

    let content = object_of(100_000);
    server.put_object("my-bucket", "a.bin", content.clone());

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    let offset = 40_960u64;
    let length = 16 * 1024usize;

    reader.seek(std::io::SeekFrom::Start(offset)).await.unwrap();

    let mut page = vec![0u8; length];
    reader.read_exact(&mut page).await.unwrap();

    assert_eq!(page, content[offset as usize..offset as usize + length]);
    assert_eq!(reader.position(), offset + length as u64);
}

/// One `read_exact` of a page is **one** `GET`, for exactly that range - no read-ahead,
/// no splitting.
#[tokio::test]
async fn one_read_exact_of_a_page_is_one_get() {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(100_000));

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();
    reader.seek(std::io::SeekFrom::Start(3_000)).await.unwrap();

    let mut page = vec![0u8; 3 * 1024];
    reader.read_exact(&mut page).await.unwrap();

    // The HEAD that opened it, and one GET. Nothing else.
    assert_eq!(server.request_count(), 2);

    let captured = server.captured();
    assert_eq!(captured[1].method, "GET");
    assert_eq!(captured[1].target, "/my-bucket/a.bin");
    // Inclusive offsets: 3000 + 3072 - 1.
    assert_eq!(captured[1].header("range"), Some("bytes=3000-6071"));
    assert!(captured[1].signature_valid);
}

/// Reading on from where the last read stopped, without seeking - the sequential case.
#[tokio::test]
async fn consecutive_reads_continue_where_the_last_one_stopped() {
    use tokio::io::AsyncReadExt;

    let server = FakeS3::start().await;
    let client = server.client();

    let content = object_of(10_000);
    server.put_object("my-bucket", "a.bin", content.clone());

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    let mut first = vec![0u8; 100];
    reader.read_exact(&mut first).await.unwrap();

    let mut second = vec![0u8; 100];
    reader.read_exact(&mut second).await.unwrap();

    assert_eq!(first, content[..100]);
    assert_eq!(second, content[100..200]);
    assert_eq!(reader.position(), 200);

    let captured = server.captured();
    assert_eq!(captured.len(), 3);
    assert_eq!(captured[1].header("range"), Some("bytes=0-99"));
    assert_eq!(captured[2].header("range"), Some("bytes=100-199"));
}

/// `Current` and `End` are resolved against the position and the size the `HEAD`
/// reported - neither costs a request.
#[tokio::test]
async fn relative_seeks_land_where_they_should() {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let server = FakeS3::start().await;
    let client = server.client();

    let content = object_of(1_000);
    server.put_object("my-bucket", "a.bin", content.clone());

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    assert_eq!(
        reader.seek(std::io::SeekFrom::Start(100)).await.unwrap(),
        100
    );
    assert_eq!(
        reader.seek(std::io::SeekFrom::Current(50)).await.unwrap(),
        150
    );
    assert_eq!(
        reader.seek(std::io::SeekFrom::Current(-25)).await.unwrap(),
        125
    );
    assert_eq!(reader.seek(std::io::SeekFrom::End(-10)).await.unwrap(), 990);
    assert_eq!(reader.seek(std::io::SeekFrom::End(0)).await.unwrap(), 1_000);

    // Not one request so far: only the HEAD that opened it.
    assert_eq!(server.request_count(), 1);

    // And the position a relative seek left behind is the one that gets read.
    reader.seek(std::io::SeekFrom::End(-4)).await.unwrap();
    let mut tail = [0u8; 4];
    reader.read_exact(&mut tail).await.unwrap();
    assert_eq!(tail.as_slice(), &content[996..]);
}

/// A relative seek is resolved against the position a *read* left behind, not against
/// the last seek.
#[tokio::test]
async fn seek_current_counts_from_where_reading_stopped() {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let server = FakeS3::start().await;
    let client = server.client();

    let content = object_of(1_000);
    server.put_object("my-bucket", "a.bin", content.clone());

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    let mut buffer = [0u8; 40];
    reader.read_exact(&mut buffer).await.unwrap();

    assert_eq!(
        reader.seek(std::io::SeekFrom::Current(10)).await.unwrap(),
        50
    );

    let mut next = [0u8; 4];
    reader.read_exact(&mut next).await.unwrap();
    assert_eq!(next.as_slice(), &content[50..54]);
}

/// Seeking before the start of the object is refused, and refused *without* a request.
#[tokio::test]
async fn seeking_before_the_start_is_invalid_input() {
    use tokio::io::AsyncSeekExt;

    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(1_000));

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    let err = reader
        .seek(std::io::SeekFrom::Current(-1))
        .await
        .unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

    let err = reader
        .seek(std::io::SeekFrom::End(-1_001))
        .await
        .unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

    // The failed seeks left the position alone, and nothing went out.
    assert_eq!(reader.position(), 0);
    assert_eq!(server.request_count(), 1);
}

/// At the end and past it, a read is end-of-file: zero bytes, and **no request** - the
/// size has been known since the `HEAD`. Seeking past the end is allowed, exactly as it
/// is on a file.
#[tokio::test]
async fn reading_at_or_past_the_end_returns_nothing_and_asks_nothing() {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(1_000));

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    reader.seek(std::io::SeekFrom::Start(1_000)).await.unwrap();
    let mut buffer = [0u8; 64];
    assert_eq!(reader.read(&mut buffer).await.unwrap(), 0);

    reader
        .seek(std::io::SeekFrom::Start(10_000_000))
        .await
        .unwrap();
    assert_eq!(reader.read(&mut buffer).await.unwrap(), 0);

    // Still only the HEAD that opened it.
    assert_eq!(server.request_count(), 1);
}

/// A `read_exact` that runs off the end must fail, not come back short: a caller that
/// asked for a page and got half of one would parse the half as the page.
#[tokio::test]
async fn a_read_exact_crossing_the_end_is_unexpected_eof() {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(1_000));

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();
    reader.seek(std::io::SeekFrom::Start(990)).await.unwrap();

    let mut page = [0u8; 64];
    let err = reader.read_exact(&mut page).await.unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);

    // The range that *was* readable was never asked for past the end of the object -
    // that would be a 416 rather than an end of file.
    let captured = server.captured();
    assert_eq!(captured[1].header("range"), Some("bytes=990-999"));
}

/// A `206` that delivers less than the range it acknowledged is a truncation, not a
/// short read.
#[tokio::test]
async fn a_body_shorter_than_the_range_is_unexpected_eof() {
    use tokio::io::AsyncReadExt;

    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(1_000));

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    // Queued after opening, so it answers the GET and not the HEAD.
    server.push_reply(206, "short");

    let mut page = [0u8; 64];
    let err = reader.read_exact(&mut page).await.unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

/// A server that ignores `Range` and returns the whole object is an error, not 64 bytes
/// taken off the front of something else.
#[tokio::test]
async fn a_range_answered_with_200_is_an_error_for_the_reader_too() {
    use tokio::io::AsyncReadExt;

    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(1_000));

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    server.push_reply(200, "the whole object, which is not what was asked for");

    let mut page = [0u8; 64];
    let err = reader.read_exact(&mut page).await.unwrap_err();

    assert!(err.to_string().contains("ignored the Range header"));
}

/// "There is no such object" is answered when the reader is *opened*, and as the typed
/// error - not as an `io::Error` at the first read.
#[tokio::test]
async fn a_missing_key_is_reported_when_the_reader_is_opened() {
    let server = FakeS3::start().await;
    let client = server.client();

    // Something is stored, so the server is serving objects - just not this one.
    server.put_object("my-bucket", "a.bin", object_of(10));

    let err = client
        .open_reader("my-bucket", "missing.bin")
        .await
        .unwrap_err();

    assert!(err.is_key_not_found());
}

/// Same for `get_object_size` on its own: a `HEAD` carries no body, so the bare `404` is
/// all there is to go on.
#[tokio::test]
async fn a_missing_key_has_no_size() {
    let server = FakeS3::start().await;
    let client = server.client();

    server.push_reply(404, "");

    let err = client
        .get_object_size("my-bucket", "missing.bin")
        .await
        .unwrap_err();

    assert!(err.is_key_not_found());
}

/// Everything that is not a missing key keeps the `S3Error` reachable through the
/// `io::Error`, so a consumer can tell a transport failure from a refusal.
#[tokio::test]
async fn a_failed_read_keeps_the_typed_error_as_its_source() {
    use tokio::io::AsyncReadExt;

    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(1_000));

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    server.push_reply(
        403,
        "<Error><Code>AccessDenied</Code><Message>no</Message></Error>",
    );

    let mut page = [0u8; 64];
    let err = reader.read_exact(&mut page).await.unwrap_err();

    let s3_error = err
        .get_ref()
        .and_then(|err| err.downcast_ref::<my_s3::S3Error>())
        .expect("the S3Error has to survive as the source");

    assert_eq!(s3_error.get_status_code(), Some(403));
    assert!(!s3_error.is_retryable());

    // Nothing that identifies the credentials leaks into the rendered message.
    let rendered = err.to_string();
    assert!(!rendered.contains(fake_s3::ACCESS_KEY));
    assert!(!rendered.contains(fake_s3::SECRET_KEY));
    assert!(!rendered.to_lowercase().contains("signature="));
}

/// Two readers over the same object are two independent positions.
#[tokio::test]
async fn two_readers_do_not_share_a_position() {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let server = FakeS3::start().await;
    let client = server.client();

    let content = object_of(1_000);
    server.put_object("my-bucket", "a.bin", content.clone());

    let mut first = client.open_reader("my-bucket", "a.bin").await.unwrap();
    let mut second = client.open_reader("my-bucket", "a.bin").await.unwrap();

    first.seek(std::io::SeekFrom::Start(10)).await.unwrap();
    second.seek(std::io::SeekFrom::Start(900)).await.unwrap();

    let mut from_first = [0u8; 8];
    let mut from_second = [0u8; 8];
    first.read_exact(&mut from_first).await.unwrap();
    second.read_exact(&mut from_second).await.unwrap();

    assert_eq!(from_first.as_slice(), &content[10..18]);
    assert_eq!(from_second.as_slice(), &content[900..908]);
}

/// `AsyncReadExt` and `AsyncSeekExt` need `Unpin`, and moving a reader onto another
/// tokio task needs `Send`. Both are load-bearing for the consumer, so they are pinned
/// here rather than left to be discovered by a compile error somewhere else.
#[test]
fn a_reader_is_send_and_unpin() {
    fn assert_send_and_unpin<T: Send + Unpin>() {}

    assert_send_and_unpin::<my_s3::S3Reader>();
}

/// And actually move one across a task boundary, which is what a consumer reading pages
/// in a spawned job does.
#[tokio::test]
async fn a_reader_survives_being_moved_to_another_task() {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let server = FakeS3::start().await;
    let client = server.client();

    let content = object_of(1_000);
    server.put_object("my-bucket", "a.bin", content.clone());

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    let page = tokio::spawn(async move {
        reader.seek(std::io::SeekFrom::Start(500)).await.unwrap();
        let mut page = [0u8; 16];
        reader.read_exact(&mut page).await.unwrap();
        page
    })
    .await
    .unwrap();

    assert_eq!(page.as_slice(), &content[500..516]);
}

/// Seeking out from under a request that is still in flight is refused, loudly. The
/// bytes on their way belong to an offset that would no longer exist, and silently
/// dropping the request is the kind of thing that turns into a wrong page much later.
#[tokio::test]
async fn seeking_while_a_read_is_in_flight_is_refused() {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let server = FakeS3::start().await;
    let client = server.client();

    server.put_object("my-bucket", "a.bin", object_of(1_000));

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    // Only now, so the HEAD that opened the reader was not slowed down.
    server.delay_every_reply(Duration::from_millis(500));

    let mut page = [0u8; 8];
    let timed_out =
        tokio::time::timeout(Duration::from_millis(20), reader.read_exact(&mut page)).await;
    assert!(timed_out.is_err(), "the read had to still be in flight");

    let err = reader.seek(std::io::SeekFrom::Start(0)).await.unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::Other);
    assert!(err.to_string().contains("in flight"));
}

/// A read that was cancelled leaves its `GET` in flight. Coming back with a *smaller*
/// buffer must not lose the rest of the range that was already paid for - and must not
/// issue a second `GET` for bytes that are already here.
#[tokio::test]
async fn a_cancelled_read_is_resumed_without_a_second_get() {
    use tokio::io::AsyncReadExt;

    let server = FakeS3::start().await;
    let client = server.client();

    let content = object_of(1_000);
    server.put_object("my-bucket", "a.bin", content.clone());

    let mut reader = client.open_reader("my-bucket", "a.bin").await.unwrap();

    server.delay_every_reply(Duration::from_millis(500));

    // Asks for 16 bytes, then gives up waiting - the GET for bytes=0-15 stays in flight.
    let mut wide = [0u8; 16];
    let timed_out =
        tokio::time::timeout(Duration::from_millis(20), reader.read_exact(&mut wide)).await;
    assert!(timed_out.is_err());

    server.delay_every_reply(Duration::ZERO);

    // Half the buffer this time. The other half of the answer has to be kept, not
    // dropped.
    let mut first = [0u8; 8];
    reader.read_exact(&mut first).await.unwrap();
    assert_eq!(first.as_slice(), &content[..8]);

    let mut second = [0u8; 8];
    reader.read_exact(&mut second).await.unwrap();
    assert_eq!(second.as_slice(), &content[8..16]);

    assert_eq!(reader.position(), 16);

    // The HEAD, and the single GET that was started before the cancellation.
    assert_eq!(server.request_count(), 2);
    assert_eq!(server.captured()[1].header("range"), Some("bytes=0-15"));
}

// ---------------------------------------------------------------------------
// HTTP version
// ---------------------------------------------------------------------------

/// What every HTTP/2 connection opens with (RFC 9113 §3.4), before a single frame.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// `use_h2` has to reach the wire, not only the builder. Over `http://` there is no ALPN
/// to negotiate it, so the client opens with the preface straight away - which is what
/// a raw socket can see without an HTTP/2 server behind it.
#[tokio::test]
async fn use_h2_opens_the_connection_with_the_http2_preface() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());

    let client = my_s3::S3Client::new(
        fake_s3::ACCESS_KEY,
        fake_s3::SECRET_KEY,
        fake_s3::REGION,
        endpoint,
    )
    .use_h2();

    let request = tokio::spawn(async move { client.check_if_bucket_exists("my-bucket").await });

    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("the client never connected")
        .unwrap();

    let mut opening = vec![0u8; H2_PREFACE.len()];
    tokio::time::timeout(
        Duration::from_secs(10),
        tokio::io::AsyncReadExt::read_exact(&mut socket, &mut opening),
    )
    .await
    .expect("the client sent less than a preface")
    .unwrap();

    assert_eq!(
        opening,
        H2_PREFACE,
        "got {:?}",
        String::from_utf8_lossy(&opening)
    );

    // Nobody answers, so the request can only fail - but it has to end.
    drop(socket);
    drop(listener);
    let result = tokio::time::timeout(Duration::from_secs(30), request)
        .await
        .expect("the request outlived its connection")
        .unwrap();
    assert!(result.is_err(), "got {:?}", result);
}

/// `fl-url` streams a request body over HTTP/1.1 only, and `use_h2` is documented not to
/// change that. `FakeS3` speaks nothing but HTTP/1.1, so the upload landing intact is
/// the proof.
#[tokio::test]
async fn a_streamed_upload_stays_on_http1_under_use_h2() {
    let server = FakeS3::start().await;
    let client = server.client().use_h2();

    let content = pattern(300 * 1024);

    client
        .upload_streamed(
            "my-bucket",
            "big.bin",
            body_from(content.clone(), 64 * 1024),
            content.len(),
            UPLOAD_TIMEOUT,
        )
        .await
        .unwrap();

    let captured = server.captured();
    assert_eq!(captured.len(), 1);
    assert!(captured[0].signature_valid, "{:?}", captured[0]);
    assert_eq!(captured[0].body, content);
}

// ---------------------------------------------------------------------------
// Every future the client hands out is Send
// ---------------------------------------------------------------------------

/// Takes the value rather than a type parameter: what has to be `Send` is the future a
/// method *returns*, and that type has no name to write down.
fn assert_send<T: Send>(_: T) {}

/// Every public `async fn` must return a `Send` future, or it cannot be awaited inside
/// `tokio::spawn`, an `#[async_trait]` method, or anything else that moves work between
/// threads. Nothing is polled - this only has to compile - and the borrows are ordinary
/// lifetimes rather than `'static`, because that is how a service holds its client.
///
/// Checking the returned *types* (`S3Reader: Send`, `S3UploadWriter: Send`) does not
/// catch this: a future can fail to be `Send` while every type it produces is. The
/// retrying uploads once did exactly that - an `AsyncFnMut` closure in the retry loop
/// left their futures `Send` only for some lifetimes, which the compiler reports as
/// "implementation of `Send` is not general enough".
#[test]
fn client_futures_are_send() {
    fn check<'a>(
        client: &'a my_s3::S3Client,
        bucket_name: &'a str,
        key: &'a str,
        stream: &'a mut my_s3::S3DownloadStream,
    ) {
        let timeout = Duration::from_secs(1);

        assert_send(client.upload(bucket_name, key, Vec::new(), timeout));
        assert_send(client.upload_streamed(
            bucket_name,
            key,
            tokio::sync::mpsc::channel::<Vec<u8>>(1).1,
            0,
            timeout,
        ));
        assert_send(
            client.upload_streamed_with_retries(bucket_name, key, 0, timeout, 3, || {
                tokio::sync::mpsc::channel::<Vec<u8>>(1).1
            }),
        );
        assert_send(client.upload_with_writer(
            bucket_name,
            key,
            0,
            timeout,
            |mut writer| async move { writer.shutdown().await },
        ));
        assert_send(client.upload_with_writer_with_retries(
            bucket_name,
            key,
            0,
            timeout,
            3,
            |mut writer| async move { writer.shutdown().await },
        ));
        // Only type-checked, never run: `start_upload` itself needs a runtime.
        let (_writer, handle) = client.start_upload(bucket_name, key, 0, timeout);
        assert_send(handle.finish());
        assert_send(client.download_file(bucket_name, key));
        assert_send(client.download_file_range(bucket_name, key, 0, None));
        assert_send(stream.get_next_chunk());
        assert_send(client.open_reader(bucket_name, key));
        assert_send(client.get_object_size(bucket_name, key));
        assert_send(client.list_objects_v2(
            bucket_name,
            my_s3::S3ListObjectsRequest {
                prefix: Some(key),
                ..Default::default()
            },
        ));
        assert_send(client.delete_file(bucket_name, key));
        assert_send(client.copy_file(bucket_name, key, bucket_name, key));
        assert_send(client.create_bucket(bucket_name));
        assert_send(client.create_bucket_if_not_exists(bucket_name));
        assert_send(client.get_bucket_location(bucket_name));
        assert_send(client.check_if_bucket_exists(bucket_name));
    }

    let _ = check;
}
