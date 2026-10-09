use std::sync::Arc;

use tokio::task::JoinHandle;

use super::S3Error;
use super::upload_writer::UploadWriterState;

/// The other half of [`S3Client::start_upload`]: the upload itself, running on a task of
/// its own, and the one place that says whether the object was stored.
///
/// The [`S3UploadWriter`] it came with can go anywhere - into a factory, into code that
/// only knows `AsyncWrite` - and this stays with whoever needs the answer.
///
/// # `finish` is the only proof
///
/// A writer's `shutdown()` returning `Ok` means the body was handed over, not that the
/// storage has it. Only [`Self::finish`] waits for the answer.
///
/// # Dropping it cancels the upload
///
/// A handle dropped without `finish` aborts the upload task, so an object whose result
/// nobody waits for does not quietly land in the bucket. The writer finds out at once: its
/// next write, flush or `shutdown` fails with [`std::io::ErrorKind::BrokenPipe`].
///
/// That is a promise about an upload that has **not been answered yet**. A handle dropped
/// after the whole body went out races the storage: the object may already have been
/// committed when the connection is cut, and nothing will say so. After a drop the object
/// may or may not be there.
///
/// [`S3Client::start_upload`]: crate::S3Client::start_upload
/// [`S3UploadWriter`]: crate::S3UploadWriter
pub struct S3UploadHandle {
    upload: JoinHandle<Result<(), S3Error>>,
    state: Arc<UploadWriterState>,
    /// For the messages, and for the caller's bookkeeping: the handle is what outlives the
    /// writer, and an archive with 257 of them in flight needs to know which one failed.
    bucket_name: String,
    key: String,
}

impl S3UploadHandle {
    pub(crate) fn new(
        upload: JoinHandle<Result<(), S3Error>>,
        state: Arc<UploadWriterState>,
        bucket_name: &str,
        key: &str,
    ) -> Self {
        Self {
            upload,
            state,
            bucket_name: bucket_name.to_string(),
            key: key.to_string(),
        }
    }

    pub fn bucket_name(&self) -> &str {
        self.bucket_name.as_str()
    }

    pub fn key(&self) -> &str {
        self.key.as_str()
    }

    /// The `Content-Length` the upload was started with.
    pub fn content_length(&self) -> u64 {
        self.state.content_length()
    }

    /// How many bytes have been handed to the upload so far. Not how many the storage
    /// has - that is only known once [`Self::finish`] returns.
    pub fn bytes_sent(&self) -> u64 {
        self.state.sent()
    }

    /// Waits for the upload to end, and says whether the object was stored.
    ///
    /// Call it **after** the writer's `shutdown()`, or after the writer has been dropped.
    ///
    /// It waits for the upload, and an upload normally ends with its body - so while the
    /// writer is alive and still owes bytes, this waits for the writer. It returns sooner
    /// only when the upload fails first: the storage refuses it, the connection dies,
    /// `upload_timeout` runs out. The writer and the handle may well live on different
    /// tasks.
    ///
    /// **Nothing bounds the wait before the first chunk.** `upload_timeout` covers the
    /// request, and the request starts only when the writer hands over a chunk (a full
    /// one, or a flush) or ends the body. Awaited on the task that holds a writer which
    /// has not got that far, this never returns. Past the first chunk it ends at the
    /// latest in the `upload_timeout` error.
    ///
    /// # What comes back
    ///
    /// The same rules [`S3Client::upload_with_writer`] settles by:
    ///
    /// - **`Ok(())`** - the storage accepted it and every declared byte went out.
    /// - **The S3 error** - the upload failed: the storage refused it, the connection died,
    ///   the timeout ran out. Ask [`S3Error::is_retryable`]. This is also what comes back
    ///   while the writer is still alive, because a writer that has not ended the body
    ///   cannot have been what broke it.
    /// - **[`S3Error::UploadProducerFailed`] with [`std::io::ErrorKind::UnexpectedEof`]** -
    ///   the body was ended with fewer bytes than declared: the writer was dropped early,
    ///   or `shutdown()` was never called and the last partial chunk went nowhere. Never
    ///   retryable.
    /// - **[`S3Error::Other`]** - the upload task itself panicked, or was cancelled by a
    ///   runtime shutting down. Never a success, never blamed on the writer, never
    ///   retryable.
    ///
    /// The handle only knows byte counts. If the code writing into the writer stopped
    /// for a reason of its own, keep that error: here it can only show up as the short
    /// body it left behind.
    ///
    /// # No retries
    ///
    /// A streamed body is consumed as it is sent, so there is nothing here to repeat. When
    /// the error [`S3Error::is_retryable`], start a new upload with
    /// [`S3Client::start_upload`] and write the body again **from the first byte**.
    ///
    /// # Dropping this future cancels the upload
    ///
    /// It owns the handle, so a `tokio::time::timeout` around it, or a `select!` branch
    /// that loses, aborts the upload for good. For a bounded wait that does not cancel,
    /// spawn it and put the timeout on the `JoinHandle` instead.
    ///
    /// [`S3Client::upload_with_writer`]: crate::S3Client::upload_with_writer
    /// [`S3Client::start_upload`]: crate::S3Client::start_upload
    pub async fn finish(mut self) -> Result<(), S3Error> {
        // Awaited through the field rather than taken out of it: the `JoinHandle` stays
        // inside `self`, so if this future is dropped half-way `Drop` still aborts the
        // upload. Nobody waiting is exactly when the object must not land.
        let upload_result = match (&mut self.upload).await {
            Ok(upload_result) => upload_result,

            // Decided before the body is looked at: a task that panicked tells nothing
            // about the writer, and a short body next to it would read as the writer's
            // fault.
            Err(join_error) => {
                return Err(S3Error::Other(format!(
                    "the upload task for {}/{} did not finish: {}",
                    self.bucket_name, self.key, join_error
                )));
            }
        };

        let body_failure = match (&upload_result, self.state.body_ended()) {
            // A 2xx has to mean every declared byte went out, whatever the writer is up
            // to - a storage that answers early is not vouching for a body it never got.
            (Ok(()), _) => self.state.short_body_error(),

            // The body has ended, so its length is final and `settle` can tell a writer
            // that abandoned it from an upload that died under it.
            (Err(_), true) => self.state.short_body_error(),

            // The writer is still alive. It has not abandoned anything; the upload died
            // first, and its error is the reason. The writer finds out as `BrokenPipe`.
            (Err(_), false) => None,
        };

        self.state.settle(upload_result, body_failure)
    }
}

/// A handle that went through [`S3UploadHandle::finish`] holds a finished task, and is
/// left alone: its writer, if it is still around, keeps behaving as the finished upload
/// left it.
///
/// Otherwise the upload is cancelled. `abort` only *schedules* that - the task lets go of
/// the channel when the runtime next gets to it, and until then the writer's sends would
/// still find room - so the end of the upload is recorded first, where the writer checks
/// before every write. Neither needs a runtime context, so a handle dropped during
/// shutdown is fine.
impl Drop for S3UploadHandle {
    fn drop(&mut self) {
        if self.upload.is_finished() {
            return;
        }

        self.state.mark_upload_ended();
        self.upload.abort();
    }
}

/// Written by hand: the shared state has no `Debug`. What is printed identifies the
/// object and how far its upload has got.
impl std::fmt::Debug for S3UploadHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3UploadHandle")
            .field("bucket_name", &self.bucket_name)
            .field("key", &self.key)
            .field("content_length", &self.content_length())
            .field("bytes_sent", &self.bytes_sent())
            .field("finished", &self.upload.is_finished())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::S3UploadWriter;

    /// A panicking upload task next to a writer that is still holding a partial body. The
    /// verdict must be the task's failure: a short body plus "the channel never closed
    /// under the writer" is otherwise exactly what blames the writer.
    #[tokio::test]
    async fn an_upload_task_that_panics_is_not_blamed_on_the_writer() {
        let (mut writer, _body, state) = S3UploadWriter::new("my-bucket", "a.bin", 1_000, 512);

        writer.write_all(&[7u8; 100]).await.unwrap();

        let upload = tokio::spawn(async { panic!("the upload task broke") });
        let handle = S3UploadHandle::new(upload, state, "my-bucket", "a.bin");

        let err = handle.finish().await.unwrap_err();

        assert!(
            !err.is_upload_producer_failed(),
            "a panic in the upload task is not the writer's failure, got: {}",
            err
        );
        assert!(
            err.to_string()
                .contains("upload task for my-bucket/a.bin did not finish"),
            "got: {}",
            err
        );
        assert!(!err.is_retryable());

        drop(writer);
    }

    /// The case the early return exists for: the task panicked *and* the body has ended
    /// short, with no send ever finding the channel closed. Without deciding the panic
    /// first, those are exactly the inputs that settle as the writer's failure.
    #[tokio::test]
    async fn an_upload_task_that_panics_is_not_blamed_on_a_body_that_ended_short() {
        let (mut writer, _body, state) = S3UploadWriter::new("my-bucket", "a.bin", 1_000, 512);

        // One 512-byte chunk sent, 88 bytes left in the buffer and lost with the writer.
        writer.write_all(&[7u8; 600]).await.unwrap();
        drop(writer);

        let upload = tokio::spawn(async { panic!("the upload task broke") });
        let handle = S3UploadHandle::new(upload, state, "my-bucket", "a.bin");

        let err = handle.finish().await.unwrap_err();

        assert!(
            !err.is_upload_producer_failed(),
            "a panic in the upload task is not the writer's failure, got: {}",
            err
        );
        assert!(
            err.to_string()
                .contains("upload task for my-bucket/a.bin did not finish"),
            "got: {}",
            err
        );
    }

    /// The same short body, once the writer has ended it: now the short body *is* the
    /// verdict, and the storage's complaint is only its consequence.
    #[tokio::test]
    async fn a_body_ended_short_is_the_writers_failure_even_if_the_upload_failed() {
        let (mut writer, _body, state) = S3UploadWriter::new("my-bucket", "a.bin", 1_000, 512);

        writer.write_all(&[7u8; 600]).await.unwrap();
        drop(writer);

        let upload =
            tokio::spawn(async { Err(S3Error::Other("the storage saw a short body".to_string())) });
        let handle = S3UploadHandle::new(upload, state, "my-bucket", "a.bin");

        let err = handle.finish().await.unwrap_err();

        let io_error = err
            .get_upload_producer_error()
            .expect("a body ended short is the writer's failure");
        assert_eq!(io_error.kind(), std::io::ErrorKind::UnexpectedEof);
        assert!(
            io_error.to_string().contains("512 of the 1000"),
            "got: {}",
            io_error
        );
    }

    /// And while the writer is still alive the upload's own error stands, retryable or not
    /// as it is - the writer has not ended anything it could be blamed for.
    #[tokio::test]
    async fn an_upload_that_fails_under_a_live_writer_keeps_its_own_error() {
        let (mut writer, _body, state) = S3UploadWriter::new("my-bucket", "a.bin", 1_000, 512);

        writer.write_all(&[7u8; 600]).await.unwrap();

        let upload = tokio::spawn(async {
            Err(S3Error::UnexpectedStatusCode {
                status_code: 503,
                error_code: None,
                body: String::new(),
            })
        });
        let handle = S3UploadHandle::new(upload, state, "my-bucket", "a.bin");

        let err = handle.finish().await.unwrap_err();

        assert_eq!(err.get_status_code(), Some(503));
        assert!(err.is_retryable());

        drop(writer);
    }
}
