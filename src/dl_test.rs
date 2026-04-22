use std::time::{Duration, Instant};

use reqwest::IntoUrl;

pub trait ProgressCallback {
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

pub struct NoOpProgress;

pub async fn download<U, C>(
    url: U,
    mut callback: C,
    time_limit: Duration,
) -> reqwest::Result<(u64, Duration)>
where
    U: IntoUrl,
    C: ProgressCallback,
{
    let mut response = reqwest::get(url).await?.error_for_status()?;
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
