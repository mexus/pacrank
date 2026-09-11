use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use display_error_chain::DisplayErrorChain;
use futures_util::Stream;
use rand::{Rng, RngExt};
use reqwest::IntoUrl;

/// Fraction of a probe interval used as random jitter, as in "±10%".
///
/// Spreading probe starts over a tenth of their interval keeps the phase's
/// requests from marching in lockstep — a burst of simultaneous HEADs is
/// exactly what the interval exists to prevent.
const JITTER_FRACTION: f64 = 0.1;

/// Grace added to a phase deadline when capping a probe with `timeout_at`.
///
/// A request launched just before the deadline is allowed this much time to
/// settle past it, so a hung connection is cancelled by us instead of
/// bleeding into whatever phase follows. The country survey's adaptive
/// cold-probe cap sizes itself against this same grace
/// (`SETUP_TIMEOUT_INITIAL` in `country_detect`).
pub(crate) const DEADLINE_GRACE: Duration = Duration::from_millis(500);

/// A self-tuning cap for cold probes, shared by every stream of one
/// measurement run.
///
/// Starts at `initial` and, as cold probes succeed, tightens toward
/// `mean + 2 × deviation` of the observed setup latencies, clamped to
/// `[floor, initial]` — so a request that hangs stops holding a concurrency
/// slot for the full worst case once the run has learned what "normal" looks
/// like. The smoothing follows RFC 6298 (TCP's RTO estimator: gain 1/8 for
/// the mean, 1/4 for the deviation), with two departures. The multiplier is
/// 2 rather than 4: RTO protects a single connection from spurious
/// retransmits, while this cap governs a whole population whose deviation is
/// naturally large, and the caller's `floor` is what guarantees no
/// decision-relevant probe gets censored. And a probe cut off by the cap
/// feeds back as a synthetic sample at *twice* the cap's current value — the
/// RFC's own backoff-by-doubling, which also clears the integer smoothing's
/// deadzone — so repeated timeouts push the cap up, breaking the
/// survivorship spiral where an over-tight cap censors the very samples that
/// would have widened it.
///
/// Cheap to clone; clones share one state. Millisecond granularity, and the
/// integer smoothing settles within a few ms of the true mean — plenty for a
/// timeout.
#[derive(Clone)]
pub struct AdaptiveTimeout {
    inner: Arc<TimeoutState>,
}

struct TimeoutState {
    /// `(mean_ms << 32) | deviation_ms`; `0` means "no samples yet" (a real
    /// sample is never recorded below 1ms). Packing the pair into one atomic
    /// keeps mean and deviation consistent without a lock.
    state: AtomicU64,
    /// How many probes the cap has cut off — the direct measure of whether
    /// the mechanism is earning its keep on this network.
    cuts: AtomicU64,
    initial: Duration,
    floor: Duration,
}

impl AdaptiveTimeout {
    /// `initial` doubles as the ceiling; `floor` is the tightest the cap may
    /// get and belongs to the caller, who knows below which point a slow
    /// answer could still have mattered.
    pub fn new(initial: Duration, floor: Duration) -> Self {
        assert!(floor <= initial, "floor must not exceed initial");
        Self {
            inner: Arc::new(TimeoutState {
                state: AtomicU64::new(0),
                cuts: AtomicU64::new(0),
                initial,
                floor,
            }),
        }
    }

    /// How many probes the cap has cut off so far.
    pub fn timeouts(&self) -> u64 {
        self.inner.cuts.load(Ordering::Relaxed)
    }

    /// The cap's current value.
    pub fn current(&self) -> Duration {
        match self.inner.state.load(Ordering::Relaxed) {
            0 => self.inner.initial,
            state => {
                let (mean, dev) = unpack(state);
                Duration::from_millis(u64::from(mean) + 2 * u64::from(dev))
                    .clamp(self.inner.floor, self.inner.initial)
            }
        }
    }

    /// Records a successful cold probe's latency.
    pub fn observe(&self, setup: Duration) {
        let sample = u32::try_from(setup.as_millis()).unwrap_or(u32::MAX).max(1);
        let _ = self
            .inner
            .state
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |state| {
                Some(if state == 0 {
                    // RFC 6298 initialization: deviation starts at half the
                    // first sample.
                    pack(sample, sample / 2)
                } else {
                    let (mean, dev) = unpack(state);
                    let (mean, dev) = (i64::from(mean), i64::from(dev));
                    let sample = i64::from(sample);
                    // Deviation first, from the pre-update mean — RFC 6298
                    // order.
                    let dev = dev + ((sample - mean).abs() - dev) / 4;
                    let mean = mean + (sample - mean) / 8;
                    pack(saturate_u32(mean).max(1), saturate_u32(dev))
                })
            });
    }

    /// Records a cold probe cut off by the cap — see the type docs for why
    /// timeouts feed back at twice the cap's current value.
    pub fn observe_timeout(&self) {
        self.inner.cuts.fetch_add(1, Ordering::Relaxed);
        self.observe(self.current().saturating_mul(2));
    }
}

fn pack(mean: u32, dev: u32) -> u64 {
    (u64::from(mean) << 32) | u64::from(dev)
}

fn unpack(state: u64) -> (u32, u32) {
    ((state >> 32) as u32, state as u32)
}

fn saturate_u32(value: i64) -> u32 {
    value.clamp(0, i64::from(u32::MAX)) as u32
}

/// Whether [`ping_url`] should defeat caches between us and the origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheBust {
    /// Append a fresh `pacrank-bust=<nonce>` query to every probe, so an
    /// edge cache can never answer for the origin and each sample measures
    /// the full path — what unmasks a CDN front masquerading as a near
    /// mirror. Per *probe*, not per stream: a single nonce would simply get
    /// cached itself after the first request, fooling every warm sample.
    PerProbe,
    /// Probe the URL as given. Whatever answers may be a cache — which is
    /// the right thing to measure when the user's own requests would hit
    /// that same cache.
    Off,
}

/// Returns `url` with a `pacrank-bust=<nonce>` query pair appended,
/// preserving any query already present. The parameter name identifies us to
/// mirror operators reading their access logs.
fn bust_url(url: &url::Url, nonce: u64) -> url::Url {
    let mut busted = url.clone();
    busted
        .query_pairs_mut()
        .append_pair("pacrank-bust", &format!("{nonce:016x}"));
    busted
}

/// One successful latency measurement out of [`ping_url`].
#[derive(Debug, Clone, Copy)]
pub struct Probe {
    /// Time from sending the request to receiving the response headers.
    pub latency: Duration,
    /// `true` for the first probe on a stream that succeeds: with no pooled
    /// connection to reuse, it pays TCP connect and the TLS handshake on top
    /// of the request round-trip (and a DNS lookup too, unless the client's
    /// resolver cache was warmed beforehand). Warm probes measure the bare
    /// request over an established connection.
    ///
    /// This is an approximation — reqwest does not reveal whether a request
    /// actually reused a connection. A server that sends `Connection: close`
    /// makes every probe cold, and a keep-alive dropped mid-stream forces a
    /// silent reconnect; both are reported as warm. Still strictly better
    /// than treating every sample alike.
    pub cold: bool,
}

/// Runs a HEAD request against the provided URL and measures the time until a
/// *successful* response is received.
///
/// A non-2xx answer is a failure, not a sample. This is load-bearing: an
/// edge WAF that dislikes our User-Agent answers 403 straight from the
/// nearest POP in single-digit milliseconds (`mirror.krfoss.org` does
/// exactly that), and without the status check those refusals ranked as the
/// fastest "latencies" in the survey.
async fn time_to_first_byte_once<T: IntoUrl>(
    client: &reqwest::Client,
    url: T,
) -> reqwest::Result<Duration> {
    let start = Instant::now();
    let _response = client.head(url).send().await?.error_for_status()?;
    Ok(start.elapsed())
}

/// Repeatedly probes `url` with `HEAD` requests and yields each probe's
/// latency, tagged cold or warm — see [`Probe::cold`].
///
/// The stream fires its first probe immediately and then waits `interval`
/// (±10% jitter) between probes. Each probe is bounded by `until`, so a
/// stalled request cannot drag the ping phase past its deadline. The stream
/// terminates once `Instant::now() >= until`.
///
/// When `setup_timeout` is provided, the stream's cold request is
/// additionally capped by the timeout's current value, and its outcome —
/// latency or cut-off — is fed back in. Warm requests neither consult nor
/// feed it: hangs are overwhelmingly a cold-request phenomenon (SYN
/// blackholes, TLS stalls), and mixing warm round-trips into the average
/// would strangle every cold probe.
///
/// `cache_bust` decides whether each probe carries a unique query string —
/// see [`CacheBust`].
///
/// # Note
///
/// Requires a Tokio runtime — uses `tokio::time`.
pub fn ping_url(
    client: &reqwest::Client,
    url: url::Url,
    interval: Duration,
    until: Instant,
    setup_timeout: Option<AdaptiveTimeout>,
    cache_bust: CacheBust,
) -> impl Stream<Item = Result<Probe, String>> {
    // OS-seeded: we only use it for timing jitter and cache-busting nonces,
    // not anything reproducible.
    let mut rng: rand::rngs::StdRng = rand::make_rng();
    futures_util::stream::unfold(
        (true, false, Instant::now()),
        move |(is_first, had_success, last_request)| {
            let url = match cache_bust {
                CacheBust::PerProbe => bust_url(&url, rng.random()),
                CacheBust::Off => url.clone(),
            };
            let interval = jitter_duration(interval, &mut rng);
            // `reqwest::Client` is internally `Arc`-based, so cloning is a cheap
            // refcount bump — cheaper than threading a shared borrow through the
            // async state machine.
            let client = client.clone();
            let setup_timeout = setup_timeout.clone();
            async move {
                if !is_first {
                    let next_ping = last_request + interval;
                    if next_ping >= until {
                        return None;
                    }
                    tokio::time::sleep_until(next_ping.into()).await;
                }

                let is_cold = !had_success;
                // In play only for the cold request; `None` past that point.
                let setup_timeout = setup_timeout.filter(|_| is_cold);

                // `timeout_at` caps the request at the phase deadline (plus
                // grace): a hung connection gets cancelled instead of
                // bleeding into the next phase. The cold request may be
                // capped tighter still by the adaptive setup timeout.
                let mut cap = tokio::time::Instant::from(until) + DEADLINE_GRACE;
                if let Some(timeout) = &setup_timeout {
                    cap = cap.min(tokio::time::Instant::now() + timeout.current());
                }

                let result =
                    match tokio::time::timeout_at(cap, time_to_first_byte_once(&client, url)).await
                    {
                        Ok(Ok(latency)) => {
                            if let Some(timeout) = &setup_timeout {
                                timeout.observe(latency);
                            }
                            Ok(Probe {
                                latency,
                                cold: is_cold,
                            })
                        }
                        // A request *error* says nothing about duration, so it
                        // does not feed the timeout. It also leaves no pooled
                        // connection behind, so the next success is still the
                        // cold one.
                        Ok(Err(e)) => Err(DisplayErrorChain::new(e).to_string()),
                        Err(elapsed) => {
                            if let Some(timeout) = &setup_timeout {
                                timeout.observe_timeout();
                            }
                            Err(DisplayErrorChain::new(elapsed).to_string())
                        }
                    };

                let had_success = had_success || result.is_ok();
                Some((result, (false, had_success, Instant::now())))
            }
        },
    )
}

/// Applies a random jitter of ±[`JITTER_FRACTION`] to a `Duration`.
fn jitter_duration<R: Rng + ?Sized>(duration: Duration, rng: &mut R) -> Duration {
    let factor = rng.random_range(-JITTER_FRACTION..=JITTER_FRACTION);

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

    /// Jittering a known duration keeps it within ±[`JITTER_FRACTION`],
    /// across many draws of the seeded RNG.
    #[test]
    fn test_jitter_stays_within_bounds() {
        let base = Duration::from_millis(1000);

        let min_bound = Duration::from_millis(900);
        let max_bound = Duration::from_millis(1100);

        for seed in 0..5 {
            let mut rng = StdRng::seed_from_u64(seed);
            for _ in 0..1000 {
                let result = jitter_duration(base, &mut rng);
                assert!(
                    result >= min_bound && result <= max_bound,
                    "Duration {:?} fell out of bounds",
                    result
                );
            }
        }
    }

    #[test]
    fn test_zero_duration_remains_zero() {
        let mut rng = mock_rng();
        let base = Duration::ZERO;

        // 0 multiplied by anything is 0
        let result = jitter_duration(base, &mut rng);
        assert_eq!(result, Duration::ZERO);
    }

    #[test]
    fn test_max_duration_safely_clamps_without_panicking() {
        let mut rng = mock_rng();
        let base = Duration::MAX;

        // Jittering Duration::MAX upward overflows f64's bounds for Duration.
        // This ensures the upper-bound check successfully catches it.
        let result = jitter_duration(base, &mut rng);

        assert!(result <= Duration::MAX);
    }

    /// Serves every request on every connection with `status_line`, e.g.
    /// `"403 Forbidden"`. Returns the bound address.
    async fn spawn_static_server(status_line: &'static str) -> std::net::SocketAddr {
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
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {
                                let response =
                                    format!("HTTP/1.1 {status_line}\r\ncontent-length: 0\r\n\r\n");
                                if sock.write_all(response.as_bytes()).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    async fn collect_probes(addr: std::net::SocketAddr) -> Vec<Result<Probe, String>> {
        let client = reqwest::Client::new();
        let url: url::Url = format!("http://{addr}/lastsync").parse().unwrap();
        let deadline = Instant::now() + Duration::from_millis(250);
        let stream = ping_url(
            &client,
            url,
            Duration::from_millis(50),
            deadline,
            None,
            CacheBust::Off,
        );
        futures_util::pin_mut!(stream);
        let mut probes = Vec::new();
        while let Some(result) = futures_util::StreamExt::next(&mut stream).await {
            probes.push(result);
        }
        probes
    }

    #[tokio::test]
    async fn non_success_status_is_an_error_not_a_sample() {
        // The krfoss failure mode: an edge WAF answering 403 in single-digit
        // milliseconds must not rank as a fast mirror.
        let addr = spawn_static_server("403 Forbidden").await;
        let probes = collect_probes(addr).await;
        assert!(!probes.is_empty());
        for probe in probes {
            assert!(probe.is_err(), "403 must not produce a latency sample");
        }
    }

    #[tokio::test]
    async fn first_success_is_cold_rest_are_warm() {
        let addr = spawn_static_server("200 OK").await;
        let probes: Vec<Probe> = collect_probes(addr)
            .await
            .into_iter()
            .collect::<Result<_, _>>()
            .expect("all probes against a 200 server must succeed");
        assert!(probes.len() >= 2, "expected several probes, got {probes:?}");
        assert!(probes[0].cold);
        assert!(probes[1..].iter().all(|p| !p.cold));
    }

    #[test]
    fn bust_url_appends_nonce_query() {
        let base: url::Url = "https://mirror.example.org/archlinux/lastsync"
            .parse()
            .unwrap();
        let busted = bust_url(&base, 0xff);
        assert_eq!(
            busted.as_str(),
            "https://mirror.example.org/archlinux/lastsync?pacrank-bust=00000000000000ff"
        );
    }

    #[test]
    fn bust_url_preserves_existing_query() {
        let base: url::Url = "https://mirror.example.org/lastsync?a=b".parse().unwrap();
        let busted = bust_url(&base, 1);
        assert_eq!(
            busted.as_str(),
            "https://mirror.example.org/lastsync?a=b&pacrank-bust=0000000000000001"
        );
    }

    #[test]
    fn bust_url_differs_per_nonce() {
        let base: url::Url = "https://mirror.example.org/lastsync".parse().unwrap();
        assert_ne!(bust_url(&base, 1), bust_url(&base, 2));
    }

    #[test]
    fn adaptive_timeout_starts_at_initial() {
        let timeout = AdaptiveTimeout::new(Duration::from_secs(1), Duration::from_millis(100));
        assert_eq!(timeout.current(), Duration::from_secs(1));
    }

    #[test]
    fn adaptive_timeout_converges_toward_uniform_samples() {
        let timeout = AdaptiveTimeout::new(Duration::from_secs(1), Duration::from_millis(10));
        for _ in 0..200 {
            timeout.observe(Duration::from_millis(50));
        }
        // Mean settles at 50ms, deviation decays toward zero (integer
        // smoothing leaves a few ms of residue).
        let current = timeout.current();
        assert!(
            (Duration::from_millis(50)..=Duration::from_millis(80)).contains(&current),
            "expected ~50-80ms, got {current:?}"
        );
    }

    #[test]
    fn adaptive_timeout_respects_floor_and_ceiling() {
        let timeout = AdaptiveTimeout::new(Duration::from_millis(500), Duration::from_millis(200));
        for _ in 0..100 {
            timeout.observe(Duration::from_millis(5));
        }
        assert_eq!(timeout.current(), Duration::from_millis(200));
        for _ in 0..100 {
            timeout.observe(Duration::from_secs(9));
        }
        assert_eq!(timeout.current(), Duration::from_millis(500));
    }

    #[test]
    fn adaptive_timeout_timeouts_push_the_cap_up() {
        let timeout = AdaptiveTimeout::new(Duration::from_secs(1), Duration::from_millis(10));
        for _ in 0..200 {
            timeout.observe(Duration::from_millis(20));
        }
        let tightened = timeout.current();
        for _ in 0..50 {
            timeout.observe_timeout();
        }
        assert!(
            timeout.current() > tightened,
            "cut-offs must widen the cap: {tightened:?} -> {:?}",
            timeout.current()
        );
    }

    #[test]
    fn adaptive_timeout_counts_only_cut_offs() {
        let timeout = AdaptiveTimeout::new(Duration::from_secs(1), Duration::from_millis(10));
        timeout.observe(Duration::from_millis(50));
        assert_eq!(timeout.timeouts(), 0);
        timeout.observe_timeout();
        timeout.observe_timeout();
        assert_eq!(timeout.timeouts(), 2);
    }

    #[test]
    fn adaptive_timeout_submillisecond_sample_is_not_mistaken_for_empty() {
        let timeout = AdaptiveTimeout::new(Duration::from_secs(1), Duration::from_millis(1));
        timeout.observe(Duration::from_micros(10));
        // Had the sample collided with the "no samples" sentinel, current()
        // would still be the initial 1s.
        assert!(timeout.current() < Duration::from_secs(1));
    }
}
