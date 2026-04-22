use std::time::{Duration, Instant};

use display_error_chain::DisplayErrorChain;
use futures_util::Stream;
use rand::{Rng, RngExt, SeedableRng};
use reqwest::IntoUrl;

/// Runs a HEAD request against the provided URL and measures the time until any
/// response is received.
async fn time_to_first_byte_once<T: IntoUrl>(url: T) -> reqwest::Result<Duration> {
    let start = Instant::now();
    let _response = reqwest::Client::builder().build()?.head(url).send().await?;
    Ok(start.elapsed())
}

/// Repeatedly measures the time-to-first-byte on the given URL.
///
/// # Note
///
/// Requires Tokio runtime!
pub fn ping_url<T: IntoUrl + Clone>(
    url: T,
    interval: Duration,
    until: Instant,
) -> impl Stream<Item = Result<Duration, String>> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(1337);
    futures_util::stream::unfold((true, Instant::now()), move |(is_first, last_request)| {
        let url = url.clone();
        let interval = jitter_duration(interval, 0.1, &mut rng);
        async move {
            if Instant::now() >= until {
                None
            } else {
                if !is_first {
                    let next_ping = last_request + interval;
                    tokio::time::sleep_until(next_ping.into()).await;
                }
                let result = time_to_first_byte_once(url)
                    .await
                    .map_err(|e| DisplayErrorChain::new(e).to_string());
                Some((result, (false, Instant::now())))
            }
        }
    })
}

/// Applies a random jitter to a `Duration`.
///
/// `jitter_fraction` must be strictly between 0.0 and 1.0 (exclusive).
/// If it falls outside this range, the original duration is returned unchanged.
fn jitter_duration<R: Rng + ?Sized>(
    duration: Duration,
    jitter_fraction: f64,
    rng: &mut R,
) -> Duration {
    // Strict range: 0.0 < fraction < 1.0
    // This condition also safely evaluates to false if jitter_fraction is NaN.
    if !(0.0 < jitter_fraction && jitter_fraction < 1.0) {
        return duration;
    }

    let factor = rng.random_range(-jitter_fraction..=jitter_fraction);

    // Because factor is strictly > -1.0, (1.0 + factor) is always positive.
    // Mathematical underflow is impossible here.
    let jittered_secs = duration.as_secs_f64() * (1.0 + factor);

    // We still require an upper bound guard. If `duration` is near Duration::MAX,
    // adding jitter could exceed the max limit and cause from_secs_f64 to panic.
    if jittered_secs >= Duration::MAX.as_secs_f64() {
        Duration::MAX
    } else {
        Duration::from_secs_f64(jittered_secs)
    }
}

#[cfg(test)]
mod test {
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    fn mock_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    #[test]
    fn test_invalid_fractions_return_original_duration() {
        let mut rng = mock_rng();
        let base = Duration::from_secs(10);

        // 0.0 and 1.0 are explicitly excluded
        assert_eq!(jitter_duration(base, 0.0, &mut rng), base);
        assert_eq!(jitter_duration(base, 1.0, &mut rng), base);

        // Out of bounds
        assert_eq!(jitter_duration(base, -0.1, &mut rng), base);
        assert_eq!(jitter_duration(base, 1.5, &mut rng), base);

        // NaN check
        assert_eq!(jitter_duration(base, f64::NAN, &mut rng), base);
    }

    #[test]
    fn test_jitter_stays_within_bounds() {
        let mut rng = mock_rng();
        let base = Duration::from_millis(1000);
        let fraction = 0.5; // ±50%

        let min_bound = Duration::from_millis(500);
        let max_bound = Duration::from_millis(1500);

        for _ in 0..1000 {
            let result = jitter_duration(base, fraction, &mut rng);
            assert!(
                result >= min_bound && result <= max_bound,
                "Duration {:?} fell out of bounds",
                result
            );
        }
    }

    #[test]
    fn test_zero_duration_remains_zero() {
        let mut rng = mock_rng();
        let base = Duration::ZERO;

        // 0 multiplied by anything is 0
        let result = jitter_duration(base, 0.99, &mut rng);
        assert_eq!(result, Duration::ZERO);
    }

    #[test]
    fn test_max_duration_safely_clamps_without_panicking() {
        let mut rng = mock_rng();
        let base = Duration::MAX;

        // Jittering Duration::MAX upward overflows f64's bounds for Duration.
        // This ensures the upper-bound check successfully catches it.
        let result = jitter_duration(base, 0.5, &mut rng);

        assert!(result <= Duration::MAX);
    }
}
