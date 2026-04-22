use std::time::{Duration, Instant};

use reqwest::IntoUrl;

/// Callback invoked after every chunk that [`download`] reads.
///
/// `bytes` is the running total of bytes received so far. `total` is the
/// value of the response's `Content-Length` header when known, or `None`
/// (e.g. for chunked-transfer responses).
pub trait ProgressCallback {
    /// Reports the current byte count to the callback.
    fn progress(&mut self, bytes: u64, total: Option<u64>);
}

impl<F> ProgressCallback for F
where
    F: FnMut(u64, Option<u64>),
{
    fn progress(&mut self, bytes: u64, total: Option<u64>) {
        (self)(bytes, total)
    }
}

/// Downloads `url` and reports throughput as `(bytes_received, elapsed)`.
///
/// Streams the response body, invoking `callback` after each chunk. Stops as
/// soon as `time_limit` has elapsed — the purpose is to measure throughput
/// over a bounded window, not to fetch the whole file. The returned
/// `elapsed` is measured after the last chunk, so it is always a little
/// larger than `time_limit`.
pub async fn download<U, C>(
    client: &reqwest::Client,
    url: U,
    mut callback: C,
    time_limit: Duration,
) -> reqwest::Result<(u64, Duration)>
where
    U: IntoUrl,
    C: ProgressCallback,
{
    let mut response = client
        .get(url)
        // .timeout(time_limit)
        .send()
        .await?
        .error_for_status()?;
    // A 0 here typically means "unknown" (chunked transfer) rather than
    // "empty response", so we treat it the same as a missing header.
    let maybe_length = response.content_length().filter(|len| *len != 0);
    let mut downloaded = 0u64;
    let start = Instant::now();
    while let Some(chunk) = response.chunk().await? {
        downloaded += chunk.len() as u64;
        callback.progress(downloaded, maybe_length);
        if start.elapsed() >= time_limit {
            break;
        }
    }
    let elapsed = start.elapsed();
    Ok((downloaded, elapsed))
}
