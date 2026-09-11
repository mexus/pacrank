use std::time::{Duration, Instant};

use reqwest::IntoUrl;

/// Downloads `url` and reports throughput as `(bytes_received, elapsed)`.
///
/// Streams the response body, invoking `callback(bytes, total)` after each
/// chunk — `bytes` is the running total received so far, `total` the
/// response's `Content-Length` when known, or `None` (e.g. for
/// chunked-transfer responses; a 0 header means "unknown" rather than
/// "empty" and is treated the same). Stops as soon as `time_limit` has
/// elapsed — the purpose is to measure throughput over a bounded window,
/// not to fetch the whole file. The returned `elapsed` is measured after
/// the last chunk, so it is always a little larger than `time_limit`.
pub async fn download<U, F>(
    client: &reqwest::Client,
    url: U,
    mut callback: F,
    time_limit: Duration,
) -> reqwest::Result<(u64, Duration)>
where
    U: IntoUrl,
    F: FnMut(u64, Option<u64>),
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
        callback(downloaded, maybe_length);
        if start.elapsed() >= time_limit {
            break;
        }
    }
    let elapsed = start.elapsed();
    Ok((downloaded, elapsed))
}
