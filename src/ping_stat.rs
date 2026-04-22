use std::time::Duration;

use rand::{Rng, RngExt};

#[derive(Debug, Default)]
pub struct PingStatRunning {
    durations: Vec<Duration>,
    errors: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct PingStatComputed {
    low: Duration,
    high: Duration,
    median: Duration,
    errors: usize,
}

impl PingStatComputed {
    pub fn low(&self) -> Duration {
        self.low
    }

    pub fn high(&self) -> Duration {
        self.high
    }

    pub fn median(&self) -> Duration {
        self.median
    }

    pub fn errors(&self) -> usize {
        self.errors
    }
}

impl PingStatRunning {
    pub fn record_ping(&mut self, duration: Duration) {
        self.durations.push(duration);
    }

    pub fn record_error(&mut self) {
        self.errors += 1;
    }

    pub fn errors(&self) -> usize {
        self.errors
    }

    pub fn duration_avg(&self) -> Duration {
        let cnt = self.durations.len();
        if cnt == 0 {
            return Duration::ZERO;
        }
        let avg_secs = self.durations.iter().map(|d| d.as_secs_f64()).sum::<f64>() / cnt as f64;
        Duration::from_secs_f64(avg_secs)
    }

    pub fn duration_std_error(&self) -> Duration {
        let cnt = self.durations.len();
        if cnt <= 1 {
            return Duration::ZERO;
        }
        let avg_secs = self.durations.iter().map(|d| d.as_secs_f64()).sum::<f64>() / cnt as f64;
        let variance = self
            .durations
            .iter()
            .map(|d| (d.as_secs_f64() - avg_secs).powi(2))
            .sum::<f64>()
            / (cnt as f64 - 1.);
        let std_dev = variance.max(0.).sqrt();
        let std_error = std_dev / (cnt as f64).sqrt();
        Duration::from_secs_f64(std_error)
    }

    pub fn compute<R>(&self, rng: &mut R) -> PingStatComputed
    where
        R: Rng + ?Sized,
    {
        let (low, median, high) = self.bootstrap_range(rng);
        PingStatComputed {
            low,
            high,
            median,
            errors: self.errors,
        }
    }

    /// Returns a 90% confidence range with the median value at the middle: (p05, median, p95).
    pub fn bootstrap_range<R: Rng + ?Sized>(&self, rng: &mut R) -> (Duration, Duration, Duration) {
        const REPEATS: usize = 10_000;

        let durations_count = self.durations.len();
        if durations_count == 0 {
            return (Duration::ZERO, Duration::ZERO, Duration::ZERO);
        } else if durations_count == 1 {
            let the_only = self.durations[0];
            return (the_only, the_only, the_only);
        }

        let mut resampled = self.durations.clone();
        let distr = rand::distr::Uniform::new(0, durations_count).expect("Must be OK");

        let mut means = Vec::with_capacity(REPEATS);
        for _ in 0..REPEATS {
            resampled
                .iter_mut()
                .for_each(|sample| *sample = self.durations[rng.sample(distr)]);
            let mean =
                resampled.iter().map(|d| d.as_secs_f64()).sum::<f64>() / durations_count as f64;
            means.push(mean);
        }
        means.sort_by(|x, y| x.total_cmp(y));

        // 5 percentile
        let p_05 = means[REPEATS / 100 * 5 - 1];
        // median
        let median = means[REPEATS / 2 - 1];
        // 95 percentile
        let p_95 = means[REPEATS / 100 * 95 - 1];

        (
            Duration::from_secs_f64(p_05),
            Duration::from_secs_f64(median),
            Duration::from_secs_f64(p_95),
        )
    }
}
