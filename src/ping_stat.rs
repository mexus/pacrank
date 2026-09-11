use std::time::Duration;

use crate::ping_test::Probe;

/// Accumulates raw latency samples during the ping phase.
///
/// Call [`record_ping`](Self::record_ping) for each successful probe; then
/// turn the accumulator into a [`PingStatComputed`] summary via
/// [`compute`](Self::compute).
///
/// Cold and warm probes (see [`Probe::cold`]) land in separate buckets: the
/// cold one becomes the mirror's *setup* figure, and only warm samples feed
/// the summary statistics. The distinction matters because the statistics
/// run over the **mean** — with a handful of samples, one connection setup
/// (TCP + TLS, easily several times the request round-trip) would visibly
/// skew the headline number where a median would have shrugged it off.
#[derive(Debug, Default)]
pub struct PingStatRunning {
    warm: Vec<Duration>,
    setup: Option<Duration>,
}

/// Summary statistics derived from a set of [`PingStatRunning`] samples.
#[derive(Debug, Clone, Copy)]
pub struct PingStatComputed {
    mean: Duration,
    setup: Option<Duration>,
}

impl PingStatComputed {
    /// Mean of the warm samples — the headline latency figure used for
    /// ranking mirrors.
    ///
    /// The plain mean, not a median or a trimmed variant: with the two (at
    /// low jitter draws, three) warm samples the latency phase collects,
    /// every robust variant degenerates into picking one of the probes,
    /// while the average at least uses them all. (This replaced a
    /// 10 000-resample bootstrap whose median is the sample mean by
    /// construction at that sample size.)
    pub fn mean(&self) -> Duration {
        self.mean
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

    /// The warm samples recorded so far, in arrival order.
    pub fn warm(&self) -> &[Duration] {
        &self.warm
    }

    /// Whether the only success was the cold probe — the mirror answered
    /// once, paid the handshake, and never produced a warm sample.
    pub fn is_setup_only(&self) -> bool {
        self.setup.is_some() && self.warm.is_empty()
    }

    /// Median of the warm samples (upper median for even counts), or `None`
    /// with no warm samples. This is the cheap point estimate the country
    /// survey ranks by — unlike [`Self::compute`], no finalization.
    pub fn warm_median(&self) -> Option<Duration> {
        let mut warm = self.warm.clone();
        warm.sort_unstable();
        warm.get(warm.len() / 2).copied()
    }

    /// Finalizes the running statistics into an immutable [`PingStatComputed`],
    /// or `None` when there are no warm samples to compute statistics over.
    ///
    /// Pure: a mirror's summary is a function of its own samples alone — no
    /// RNG, no coupling to iteration order.
    pub fn compute(&self) -> Option<PingStatComputed> {
        if self.warm.is_empty() {
            return None;
        }
        let secs = self.warm.iter().map(|d| d.as_secs_f64()).sum::<f64>() / self.warm.len() as f64;
        Some(PingStatComputed {
            mean: Duration::from_secs_f64(secs),
            setup: self.setup,
        })
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    /// A warm-probe fixture — shared with the pipeline tests, which build
    /// the same accumulators latency_phase would have left behind.
    pub(crate) fn warm(ms: u64) -> Probe {
        Probe {
            latency: Duration::from_millis(ms),
            cold: false,
        }
    }

    pub(crate) fn cold(ms: u64) -> Probe {
        Probe {
            latency: Duration::from_millis(ms),
            cold: true,
        }
    }

    #[test]
    fn setup_only_computes_to_none() {
        let mut stat = PingStatRunning::default();
        stat.record_ping(cold(300));
        assert!(stat.is_setup_only());
        assert!(stat.compute().is_none());
    }

    #[test]
    fn no_samples_at_all_computes_to_none() {
        let stat = PingStatRunning::default();
        assert!(!stat.is_setup_only());
        assert!(stat.compute().is_none());
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
        // Identical warm samples → identical statistics, no matter how
        // heavy the setup sample was.
        let a = with_setup.compute().unwrap();
        let b = without_setup.compute().unwrap();
        assert_eq!(a.mean(), b.mean());
        assert_eq!(a.setup(), Some(Duration::from_millis(900)));
        assert_eq!(b.setup(), None);
    }

    #[test]
    fn single_warm_sample_is_the_mean() {
        let mut stat = PingStatRunning::default();
        stat.record_ping(cold(500));
        stat.record_ping(warm(42));
        let computed = stat.compute().unwrap();
        assert_eq!(computed.mean(), Duration::from_millis(42));
    }

    /// The mean averages every warm sample — with two samples the
    /// statistics can't degenerate into reporting just one of them.
    #[test]
    fn mean_averages_all_warm_samples() {
        let mut stat = PingStatRunning::default();
        stat.record_ping(warm(10));
        stat.record_ping(warm(30));
        assert_eq!(stat.compute().unwrap().mean(), Duration::from_millis(20));

        stat.record_ping(warm(20));
        assert_eq!(stat.compute().unwrap().mean(), Duration::from_millis(20));
    }

    #[test]
    fn first_cold_probe_wins() {
        // A well-formed stream yields one cold probe; if a second ever
        // arrives, the genuine (first) setup figure must be kept.
        let mut stat = PingStatRunning::default();
        stat.record_ping(cold(300));
        stat.record_ping(cold(700));
        stat.record_ping(warm(10));
        let computed = stat.compute().unwrap();
        assert_eq!(computed.setup(), Some(Duration::from_millis(300)));
    }

    /// The survey's ranking statistic: the upper median — an even count
    /// takes the slower of the two middle samples (`len/2`), which biases
    /// toward caution when picking nearby countries.
    #[test]
    fn warm_median_is_the_upper_median() {
        let mut stat = PingStatRunning::default();
        assert_eq!(stat.warm_median(), None, "no samples, no median");

        stat.record_ping(warm(42));
        assert_eq!(stat.warm_median(), Some(Duration::from_millis(42)));

        stat.record_ping(warm(10));
        assert_eq!(
            stat.warm_median(),
            Some(Duration::from_millis(42)),
            "even count: the slower middle sample wins"
        );

        // Arrival order must not matter — the median is of the sorted
        // samples, not of the arrival sequence.
        let mut shuffled = PingStatRunning::default();
        for ms in [30, 10, 50, 20, 40] {
            shuffled.record_ping(warm(ms));
        }
        assert_eq!(shuffled.warm_median(), Some(Duration::from_millis(30)));
    }
}
