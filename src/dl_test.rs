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
    let mut response = tokio::time::timeout(
        time_limit,
        async { client.get(url).send().await?.error_for_status() },
    )
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
