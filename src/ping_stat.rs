use std::time::Duration;

use rand::{Rng, RngExt};

use crate::ping_test::Probe;

/// Accumulates raw latency samples during the ping phase.
///
/// Call [`record_ping`](Self::record_ping) for each successful probe; then
/// turn the accumulator into a [`PingStatComputed`] summary via
/// [`compute`](Self::compute).
///
/// Cold and warm probes (see [`Probe::cold`]) land in separate buckets: the
/// cold one becomes the mirror's *setup* figure, and only warm samples feed
/// the bootstrap statistics. The distinction matters because the statistics
/// run over the **mean** — with a handful of samples, one connection setup
/// (TCP + TLS, easily several times the request round-trip) would visibly
/// skew the headline number where a median would have shrugged it off.
#[derive(Debug, Default)]
pub struct PingStatRunning {
    warm: Vec<Duration>,
    setup: Option<Duration>,
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
    setup: Option<Duration>,
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

    /// Latency of the cold probe: connection setup (TCP + TLS) plus one
    /// request round-trip. `None` when no cold probe succeeded — possible in
    /// principle, though a stream that produced warm samples must have had a
    /// cold success first.
    pub fn setup(&self) -> Option<Duration> {
        self.setup
    }
}

impl PingStatRunning {
    /// Records a successful probe.
    ///
    /// A cold probe is stored as the setup figure (first one wins — a
    /// well-formed probe stream produces at most one anyway); warm probes
    /// accumulate as statistics samples.
    pub fn record_ping(&mut self, probe: Probe) {
        if probe.cold {
            self.setup.get_or_insert(probe.latency);
        } else {
            self.warm.push(probe.latency);
        }
    }

    /// Latency of the cold probe recorded so far, if any — see
    /// [`PingStatComputed::setup`].
    pub fn setup(&self) -> Option<Duration> {
        self.setup
    }

    /// Whether the only success was the cold probe — the mirror answered
    /// once, paid the handshake, and never produced a warm sample.
    pub fn is_setup_only(&self) -> bool {
        self.setup.is_some() && self.warm.is_empty()
    }

    /// Finalizes the running statistics into an immutable [`PingStatComputed`],
    /// or `None` when there are no warm samples to compute statistics over.
    ///
    /// Runs the bootstrap resampling once; the provided `rng` drives the
    /// resampling draws.
    pub fn compute<R>(&self, rng: &mut R) -> Option<PingStatComputed>
    where
        R: Rng + ?Sized,
    {
        if self.warm.is_empty() {
            return None;
        }
        let (low, median, high) = self.bootstrap_range(rng);
        Some(PingStatComputed {
            low,
            high,
            median,
            setup: self.setup,
        })
    }

    /// Returns a 90% confidence range around the mean latency of the warm
    /// samples as `(p05, median, p95)`.
    ///
    /// Uses non-parametric bootstrap resampling: draw `warm.len()`
    /// samples with replacement from the observed samples, take the mean,
    /// repeat `REPEATS` times, then read off the 5th / 50th / 95th
    /// percentiles of the collected means. This gives a distribution-free
    /// estimate of how much the observed mean could vary under re-sampling,
    /// which is useful when the sample size is small (a handful of pings).
    pub fn bootstrap_range<R: Rng + ?Sized>(&self, rng: &mut R) -> (Duration, Duration, Duration) {
        const REPEATS: usize = 10_000;

        let warm_count = self.warm.len();
        // Degenerate cases: no point resampling if there's nothing to sample
        // from, or only one sample (every resample returns the same value).
        if warm_count == 0 {
            return (Duration::MAX, Duration::MAX, Duration::MAX);
        } else if warm_count == 1 {
            let the_only = self.warm[0];
            return (the_only, the_only, the_only);
        }

        // Reuse a single buffer across iterations to avoid REPEATS allocations.
        let mut resampled = self.warm.clone();
        let distr = rand::distr::Uniform::new(0, warm_count).expect("Must be OK");

        let mut means = Vec::with_capacity(REPEATS);
        for _ in 0..REPEATS {
            for sample in &mut resampled {
                *sample = self.warm[rng.sample(distr)];
            }
            let mean = resampled.iter().map(|d| d.as_secs_f64()).sum::<f64>() / warm_count as f64;
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

#[cfg(test)]
mod test {
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    fn warm(ms: u64) -> Probe {
        Probe {
            latency: Duration::from_millis(ms),
            cold: false,
        }
    }

    fn cold(ms: u64) -> Probe {
        Probe {
            latency: Duration::from_millis(ms),
            cold: true,
        }
    }

    fn rng() -> StdRng {
        StdRng::seed_from_u64(1337)
    }

    #[test]
    fn setup_only_computes_to_none() {
        let mut stat = PingStatRunning::default();
        stat.record_ping(cold(300));
        assert!(stat.is_setup_only());
        assert!(stat.compute(&mut rng()).is_none());
    }

    #[test]
    fn no_samples_at_all_computes_to_none() {
        let stat = PingStatRunning::default();
        assert!(!stat.is_setup_only());
        assert!(stat.compute(&mut rng()).is_none());
    }

    #[test]
    fn setup_does_not_leak_into_statistics() {
        let mut with_setup = PingStatRunning::default();
        with_setup.record_ping(cold(900));
        let mut without_setup = PingStatRunning::default();
        for stat in [&mut with_setup, &mut without_setup] {
            stat.record_ping(warm(10));
            stat.record_ping(warm(20));
            stat.record_ping(warm(30));
        }
        // Identical warm samples + identical rng seed → identical statistics,
        // no matter how heavy the setup sample was.
        let a = with_setup.compute(&mut rng()).unwrap();
        let b = without_setup.compute(&mut rng()).unwrap();
        assert_eq!(a.median(), b.median());
        assert_eq!(a.low(), b.low());
        assert_eq!(a.high(), b.high());
        assert_eq!(a.setup(), Some(Duration::from_millis(900)));
        assert_eq!(b.setup(), None);
    }

    #[test]
    fn single_warm_sample_collapses_the_interval() {
        let mut stat = PingStatRunning::default();
        stat.record_ping(cold(500));
        stat.record_ping(warm(42));
        let computed = stat.compute(&mut rng()).unwrap();
        let expected = Duration::from_millis(42);
        assert_eq!(computed.low(), expected);
        assert_eq!(computed.median(), expected);
        assert_eq!(computed.high(), expected);
    }

    #[test]
    fn first_cold_probe_wins() {
        // A well-formed stream yields one cold probe; if a second ever
        // arrives, the genuine (first) setup figure must be kept.
        let mut stat = PingStatRunning::default();
        stat.record_ping(cold(300));
        stat.record_ping(cold(700));
        stat.record_ping(warm(10));
        let computed = stat.compute(&mut rng()).unwrap();
        assert_eq!(computed.setup(), Some(Duration::from_millis(300)));
    }
}
