use std::time::Duration;

use rand::{Rng, RngExt};

/// Accumulates raw latency samples during the ping phase.
///
/// Call [`record_ping`](Self::record_ping) for each successful probe and
/// [`record_error`](Self::record_error) for failures; then turn the accumulator
/// into a [`PingStatComputed`] summary via [`compute`](Self::compute).
#[derive(Debug, Default)]
pub struct PingStatRunning {
    durations: Vec<Duration>,
    errors: usize,
}

/// Summary statistics derived from a set of [`PingStatRunning`] samples.
///
/// `low` and `high` are the bounds of a 90% bootstrap confidence interval
/// around the mean latency; `median` is the bootstrap median. See
/// [`PingStatRunning::bootstrap_range`] for the derivation.
#[derive(Debug, Clone, Copy)]
pub struct PingStatComputed {
    low: Duration,
    high: Duration,
    median: Duration,
    errors: usize,
}

impl PingStatComputed {
    /// Lower bound of the 90% confidence interval (5th percentile of the
    /// bootstrap means).
    pub fn low(&self) -> Duration {
        self.low
    }

    /// Upper bound of the 90% confidence interval (95th percentile of the
    /// bootstrap means).
    pub fn high(&self) -> Duration {
        self.high
    }

    /// Median of the bootstrap means — the headline latency figure used for
    /// ranking mirrors.
    pub fn median(&self) -> Duration {
        self.median
    }

    /// Number of probes that failed entirely (no duration recorded).
    pub fn errors(&self) -> usize {
        self.errors
    }
}

impl PingStatRunning {
    /// Records a successful probe's round-trip duration.
    pub fn record_ping(&mut self, duration: Duration) {
        self.durations.push(duration);
    }

    /// Records one failed probe (e.g. connection error, timeout).
    pub fn record_error(&mut self) {
        self.errors += 1;
    }

    /// Number of failed probes recorded so far.
    pub fn errors(&self) -> usize {
        self.errors
    }

    /// Finalizes the running statistics into an immutable [`PingStatComputed`].
    ///
    /// Runs the bootstrap resampling once; the provided `rng` drives the
    /// resampling draws.
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

    /// Returns a 90% confidence range around the mean latency as
    /// `(p05, median, p95)`.
    ///
    /// Uses non-parametric bootstrap resampling: draw `durations.len()`
    /// samples with replacement from the observed samples, take the mean,
    /// repeat `REPEATS` times, then read off the 5th / 50th / 95th
    /// percentiles of the collected means. This gives a distribution-free
    /// estimate of how much the observed mean could vary under re-sampling,
    /// which is useful when the sample size is small (a handful of pings).
    pub fn bootstrap_range<R: Rng + ?Sized>(&self, rng: &mut R) -> (Duration, Duration, Duration) {
        const REPEATS: usize = 10_000;

        let durations_count = self.durations.len();
        // Degenerate cases: no point resampling if there's nothing to sample
        // from, or only one sample (every resample returns the same value).
        if durations_count == 0 {
            return (Duration::ZERO, Duration::ZERO, Duration::ZERO);
        } else if durations_count == 1 {
            let the_only = self.durations[0];
            return (the_only, the_only, the_only);
        }

        // Reuse a single buffer across iterations to avoid REPEATS allocations.
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
        means.sort_by(f64::total_cmp);

        // Order-of-operations matters: `REPEATS * 5 / 100` keeps integer
        // truncation at the end, so smaller `REPEATS` values still land on a
        // non-zero index. The `- 1` converts 1-based percentile rank to a
        // 0-based array index.
        let p_05 = means[REPEATS * 5 / 100 - 1];
        let median = means[REPEATS / 2 - 1];
        let p_95 = means[REPEATS * 95 / 100 - 1];

        (
            Duration::from_secs_f64(p_05),
            Duration::from_secs_f64(median),
            Duration::from_secs_f64(p_95),
        )
    }
}
