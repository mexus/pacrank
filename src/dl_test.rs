use std::time::{Duration, Instant};

use display_error_chain::DisplayErrorChain;
use reqwest::IntoUrl;
use snafu::Snafu;

/// Why a throughput measurement produced no number.
///
/// The variants carry the underlying errors so the structure survives the
/// library boundary instead of collapsing into a pre-formatted string —
/// same reasoning as `ping_test::PingError`.
#[derive(Debug, Snafu)]
pub enum DlError {
    /// The request failed, or answered a non-2xx status.
    #[snafu(display("{}", DisplayErrorChain::new(&source)))]
    Http { source: reqwest::Error },
    /// Response headers did not arrive within the wait bound — the mirror
    /// accepted the connection but never started answering, so no
    /// measurement happened (this is a failure, not a zero-speed sample).
    #[snafu(display("{source}"))]
    TimedOut { source: tokio::time::error::Elapsed },
}

/// Downloads `url` and reports throughput as `(bytes_received, elapsed)`.
///
/// Streams the response body, invoking `callback(bytes, total)` after each
/// chunk — `bytes` is the running total received so far, `total` the
/// response's `Content-Length` when known, or `None` (e.g. for
/// chunked-transfer responses; a 0 header means "unknown" rather than
/// "empty" and is treated the same). Stops as soon as `time_limit` has
/// elapsed — the purpose is to measure throughput over a bounded window,
/// not to fetch the whole file. The returned `elapsed` measures the body
/// read only, so it is a little larger than `time_limit` when the window
/// closes mid-body but smaller when the body finishes early.
///
/// The window bounds *wall time*, not just inter-chunk gaps: the shared
/// client sets no read timeout, so a mirror that accepts the request and
/// then stalls would otherwise block `chunk().await` indefinitely and hang
/// the serial throughput phase. A window that closes mid-body is the normal
/// exit — the bytes counted so far are the measurement.
///
/// Response headers get the same treatment with the same budget: the wait
/// for them is bounded by `time_limit` too, and a mirror that spends it
/// without answering fails with [`DlError::TimedOut`] rather than hanging
/// `send()` forever.
///
/// Requires a Tokio runtime — uses `tokio::time`.
pub async fn download<U, F>(
    client: &reqwest::Client,
    url: U,
    mut callback: F,
    time_limit: Duration,
) -> Result<(u64, Duration), DlError>
where
    U: IntoUrl,
    F: FnMut(u64, Option<u64>),
{
    let mut response = tokio::time::timeout(time_limit, async {
        client.get(url).send().await?.error_for_status()
    })
    .await
    .map_err(|elapsed| DlError::TimedOut { source: elapsed })?
    .map_err(|source| DlError::Http { source })?;
    // A 0 here typically means "unknown" (chunked transfer) rather than
    // "empty response", so we treat it the same as a missing header.
    let maybe_length = response.content_length().filter(|len| *len != 0);
    let mut downloaded = 0u64;
    let start = Instant::now();
    let read = tokio::time::timeout(time_limit, async {
        while let Some(chunk) = response.chunk().await? {
            downloaded += chunk.len() as u64;
            callback(downloaded, maybe_length);
        }
        Ok(())
    })
    .await;
    let elapsed = start.elapsed();
    // A timed-out window is not an error — the partial byte count is the
    // measurement. Only HTTP-level errors from the read loop propagate.
    if let Ok(Err(e)) = read {
        return Err(DlError::Http { source: e });
    }
    Ok((downloaded, elapsed))
}

#[cfg(test)]
mod test {
    use super::*;

    /// Serves one canned `response` per connection after reading the
    /// request. `hold` keeps the connection open afterwards — the stall
    /// shape these tests exist for: the client must cut itself off, because
    /// the server never will.
    async fn spawn_server(response: &'static [u8], hold: bool) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    if sock.read(&mut buf).await.is_err() {
                        return;
                    }
                    if !response.is_empty() && sock.write_all(response).await.is_err() {
                        return;
                    }
                    if hold {
                        // Park with the connection open: a stalled server
                        // never hangs up, so the client's own bound is the
                        // only thing that can end this.
                        std::future::pending::<()>().await;
                    } else {
                        let _ = sock.shutdown().await;
                    }
                });
            }
        });
        addr
    }

    fn client() -> reqwest::Client {
        reqwest::Client::new()
    }

    fn url(addr: std::net::SocketAddr) -> url::Url {
        format!("http://{addr}/core.db").parse().unwrap()
    }

    /// The outer bound that turns a regression back into a failed test
    /// instead of a hung one: every case below must finish well within it.
    async fn guarded<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), fut)
            .await
            .expect("download must respect its own window, not hang")
    }

    /// A stalled body — headers sent, then nothing ever — is cut off by the
    /// window and reported as a zero-progress measurement, not an error and
    /// not a hang.
    #[tokio::test]
    async fn stalled_body_is_cut_off_by_the_window() {
        const LIMIT: Duration = Duration::from_millis(200);
        let addr = spawn_server(b"HTTP/1.1 200 OK\r\ncontent-length: 9999999\r\n\r\n", true).await;
        let (bytes, elapsed) = guarded(async {
            download(&client(), url(addr), |_, _| {}, LIMIT)
                .await
                .expect("a stalled body is a measurement of zero, not an error")
        })
        .await;
        assert_eq!(bytes, 0);
        assert!(
            elapsed >= LIMIT,
            "the window must bound wall time: {elapsed:?} < {LIMIT:?}"
        );
    }

    /// A stall *before the headers* — connection accepted, then nothing —
    /// fails once its share of the window is spent. This is the half the
    /// original wall-clock fix missed: `send()` sat outside the timeout.
    #[tokio::test]
    async fn stalled_headers_fail_after_the_window() {
        const LIMIT: Duration = Duration::from_millis(200);
        let addr = spawn_server(b"", true).await;
        let result =
            guarded(async { download(&client(), url(addr), |_, _| {}, LIMIT).await }).await;
        assert!(
            matches!(result, Err(DlError::TimedOut { .. })),
            "a never-arriving answer is a timeout, got {result:?}"
        );
    }

    /// A body that finishes early reports its own bytes and an honest
    /// sub-window elapsed — the window is a bound, not a wait.
    #[tokio::test]
    async fn early_finishing_body_reports_its_bytes() {
        const LIMIT: Duration = Duration::from_millis(200);
        let addr = spawn_server(
            b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n0123456789",
            false,
        )
        .await;
        let mut seen = Vec::new();
        let (bytes, elapsed) = guarded(async {
            download(
                &client(),
                url(addr),
                |bytes, total| seen.push((bytes, total)),
                LIMIT,
            )
            .await
            .expect("a well-behaved body must succeed")
        })
        .await;
        assert_eq!(bytes, 10);
        assert!(elapsed < LIMIT, "early finish must not pad: {elapsed:?}");
        assert_eq!(
            seen.last(),
            Some(&(10, Some(10))),
            "the callback must observe the running total and length: {seen:?}"
        );
    }

    /// A non-2xx answer is a failure, not a zero-byte sample — same rule as
    /// the ping phase, for the same reason (WAFs answer fast from nearby).
    #[tokio::test]
    async fn non_success_status_is_an_error() {
        const LIMIT: Duration = Duration::from_millis(200);
        let addr = spawn_server(
            b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n",
            false,
        )
        .await;
        let result =
            guarded(async { download(&client(), url(addr), |_, _| {}, LIMIT).await }).await;
        assert!(
            matches!(result, Err(DlError::Http { .. })),
            "404 must not measure: {result:?}"
        );
    }

    /// A response without `Content-Length` (here: connection-close framed)
    /// reports `None` for the total — and a 0 header would mean "unknown",
    /// not "empty", were it present.
    #[tokio::test]
    async fn unknown_length_reports_none() {
        const LIMIT: Duration = Duration::from_millis(200);
        let addr = spawn_server(b"HTTP/1.1 200 OK\r\n\r\n01234", false).await;
        let mut seen = Vec::new();
        let (bytes, _) = guarded(async {
            download(
                &client(),
                url(addr),
                |bytes, total| seen.push((bytes, total)),
                LIMIT,
            )
            .await
            .expect("an unframed body must still download")
        })
        .await;
        assert_eq!(bytes, 5);
        assert_eq!(
            seen.last(),
            Some(&(5, None)),
            "no Content-Length means unknown total: {seen:?}"
        );
    }
}
