//! The mirror discovery pipeline: fetch → filter → resolve → latency →
//! throughput → rank.
//!
//! Kept in the library (not the binary) so the ranking logic is testable;
//! `main.rs` contributes only the process plumbing — privilege escalation,
//! the worker protocol, and the mirrorlist rewrite.

use std::{
    collections::HashSet,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

use display_error_chain::DisplayErrorChain;
use futures_util::StreamExt;
use human_repr::HumanThroughput;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use snafu::ResultExt;
use url::Url;

use crate::{
    CountryCode, Mirror, Mirrors,
    ping_stat::{PingStatComputed, PingStatRunning},
};

/// How long the latency phase probes mirrors before statistics are computed.
///
/// At one probe a second this yields a cold probe plus two warm ones per
/// mirror — three when the jitter draws run low — enough for a stable mean
/// without stalling the run.
const LATENCY_PHASE_DURATION: Duration = Duration::from_secs(3);

/// Interval between probes against the same mirror in the latency phase
/// (jittered ±10% inside `ping_url`).
///
/// Unlike the country survey, which only needs a rough screen, this phase
/// spaces probes apart to sample latency across time rather than measuring
/// one lucky instant.
const PROBE_INTERVAL: Duration = Duration::from_secs(1);

/// A mirror whose mean latency exceeds this is dropped: even perfect
/// throughput cannot hide a second of round-trip time on every request
/// pacman makes.
const MAX_ACCEPTABLE_MEAN: Duration = Duration::from_secs(1);

/// Synchronous wrapper that spins up a Tokio runtime and runs the async
/// discovery pipeline to completion.
pub fn discover_best_mirrors(
    dl_k: NonZeroUsize,
    ping_k: NonZeroUsize,
    countries: &[CountryCode],
) -> Result<Vec<Url>, snafu::Whatever> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .whatever_context("Can't initialize Tokio")?;
    let result = rt.block_on(discover_best_mirrors_async(dl_k, ping_k, countries));
    // Never a plain `drop(rt)`: it would block until every abandoned
    // `getaddrinfo` blocking task returns. See `dns::SHUTDOWN_GRACE` for
    // why this grace exists.
    rt.shutdown_timeout(crate::dns::SHUTDOWN_GRACE);
    result
}

/// Per-mirror bookkeeping threaded through the discovery pipeline.
///
/// Two independent typestate parameters track pipeline progress:
///
/// - `PING` — [`PingStatRunning`] during the latency phase,
///   [`PingStatComputed`] after its statistics have been computed.
/// - `DL` — `Option<f64>` while throughput is being measured (some mirrors
///   will fail to produce a number), bare `f64` after ranking has filtered
///   out the failures; the latter makes "has a measured speed" a
///   compile-time guarantee.
pub(crate) struct MirrorData<PING = PingStatRunning, DL = Option<f64>> {
    mirror: Mirror,
    /// Pre-built `lastsync` URL — that endpoint is cheap to HEAD and avoids
    /// hammering a real package while measuring latency.
    last_sync_url: Url,
    ping_stat: PING,
    /// Downloaded bytes per second. When `DL = Option<f64>`, `None` means
    /// "not measured yet" (pre-throughput phase) or "measurement failed"
    /// (post-throughput, pre-rank). When `DL = f64`, ranking has already
    /// filtered out missing values.
    dl_speed: DL,
}

impl MirrorData<PingStatRunning> {
    /// Builds the bookkeeping for a freshly-fetched [`Mirror`].
    ///
    /// Fails if the mirror's URL can't accept the `lastsync` path suffix
    /// (shouldn't happen for well-formed archlinux.org entries).
    pub(crate) fn try_new(mirror: Mirror) -> Result<Self, snafu::Whatever> {
        let last_sync_url = mirror
            .lastsync_url()
            .whatever_context("Can't build the lastsync url")?;
        Ok(Self {
            mirror,
            last_sync_url,
            ping_stat: PingStatRunning::default(),
            dl_speed: None,
        })
    }

    /// Finalizes the ping statistics and transitions to the post-latency
    /// phase, or `None` when the mirror produced no warm samples to compute
    /// statistics over.
    ///
    /// Consumes `self`: the phase transition moves the per-mirror fields
    /// (URL, bookkeeping) along instead of cloning them per mirror.
    pub(crate) fn compute_pings(self) -> Option<MirrorData<PingStatComputed>> {
        let Self {
            mirror,
            last_sync_url,
            ping_stat,
            dl_speed,
        } = self;
        Some(MirrorData {
            mirror,
            last_sync_url,
            ping_stat: ping_stat.compute()?,
            dl_speed,
        })
    }
}

impl MirrorData<PingStatComputed, Option<f64>> {
    /// Lifts the mirror into the "has a measured speed" typestate, or drops
    /// it entirely if the throughput phase produced no number.
    ///
    /// Shaped for use as an [`Iterator::filter_map`] predicate — the `None`
    /// return filters the mirror out, the `Some(_)` threads it forward with
    /// `dl_speed: f64`.
    pub(crate) fn into_measured(self) -> Option<MirrorData<PingStatComputed, f64>> {
        Some(MirrorData {
            mirror: self.mirror,
            last_sync_url: self.last_sync_url,
            ping_stat: self.ping_stat,
            dl_speed: self.dl_speed?,
        })
    }
}

/// The full discovery pipeline: fetch → filter → latency → throughput → rank.
///
/// Reads top-to-bottom as a recipe; each phase lives in its own function.
async fn discover_best_mirrors_async(
    dl_k: NonZeroUsize,
    ping_k: NonZeroUsize,
    countries: &[CountryCode],
) -> Result<Vec<Url>, snafu::Whatever> {
    // Kept out of the client (see `crate::build_client`) so the resolve
    // phase can warm the very cache the client will later read from.
    let resolver = crate::dns::SurveyResolver::new();
    let client =
        crate::build_client(resolver.clone()).whatever_context("Can't build the HTTP client")?;
    let mirrors = fetch_and_filter_mirrors(&client, countries).await?;
    let mirrors = resolve_phase(&resolver, mirrors).await?;
    let mirrors = latency_phase(&client, mirrors).await;
    let mirrors = compute_and_filter_pings(mirrors, ping_k)?;
    let mirrors = throughput_phase(&client, mirrors).await;
    let mirrors = rank_by_throughput(mirrors, dl_k)?;
    print_summary(&mirrors);
    Ok(mirrors.into_iter().map(|data| data.mirror.url).collect())
}

/// Phase 1: downloads the official mirrors list and filters it down to
/// HTTP(S) mirrors in any of `countries` whose last sync is within 48h.
pub(crate) async fn fetch_and_filter_mirrors(
    client: &reqwest::Client,
    countries: &[CountryCode],
) -> Result<Vec<MirrorData<PingStatRunning>>, snafu::Whatever> {
    let Mirrors::V3(mirrors) = crate::mirrors::fetch(client)
        .await
        .whatever_context("Can't fetch or parse the mirrors list")?;
    tracing::info!("Fetched {} mirrors", mirrors.urls.len());

    // The freshness/protocol gate both stages share: see
    // `Mirror::is_fresh`. A mirror dropped by it is expected — the list
    // carries stale, non-HTTP and out-of-country entries by design — but a
    // mirror dropped because its lastsync URL cannot be built is a surprise
    // worth a log line, exactly like the parse failures lenient_mirrors
    // reports.
    let mut unbuildable = 0usize;
    let mut kept = Vec::new();
    for mirror in mirrors.urls {
        if !mirror.is_fresh() || !countries.contains(&mirror.country_code) {
            continue;
        }
        // Checked before `try_new` consumes the mirror, so the warning can
        // name the culprit; the join is cheap enough to run twice.
        if let Err(e) = mirror.lastsync_url() {
            unbuildable += 1;
            tracing::warn!("Dropping {}: {e}", mirror.url);
            continue;
        }
        // Cannot fail now that the join is known to succeed.
        if let Ok(mirror_data) = MirrorData::try_new(mirror) {
            kept.push(mirror_data);
        }
    }
    snafu::ensure_whatever!(!kept.is_empty(), "No mirrors available");
    if unbuildable > 0 {
        tracing::info!("{unbuildable} mirrors dropped: their lastsync URL could not be built.");
    }
    tracing::info!(
        "Discovered {} mirrors for {}",
        kept.len(),
        CountryCode::format_list(countries),
    );
    Ok(kept)
}

/// Phase 1b: resolves every mirror's hostname into the shared resolver cache
/// and drops mirrors whose names don't resolve.
///
/// The same split the survey performs (see `country_detect`): with the cache
/// warm, no ping sample ever includes DNS time — the client reads addresses
/// straight from the cache — and a dead name costs one lookup here instead of
/// occupying a whole ping stream for the phase.
///
/// Hostnames are deduplicated before warming (see
/// [`mirrors::distinct_by_host`]): the mirror list carries `http://X` and
/// `https://X` as two mirrors sharing one name, and the cache cannot
/// collapse two lookups that race — warmed concurrently, each twin would
/// burn its own lookup and, when the resolver is already struggling, its
/// own retry ladder. One lookup per name is also one verdict per name:
/// twins can no longer diverge over whether their host resolves.
pub(crate) async fn resolve_phase(
    resolver: &crate::dns::SurveyResolver,
    mirrors: Vec<MirrorData<PingStatRunning>>,
) -> Result<Vec<MirrorData<PingStatRunning>>, snafu::Whatever> {
    let total = mirrors.len();
    // One warm per distinct hostname, in first-seen order — see
    // `mirrors::distinct_by_host`.
    let hosts: Vec<String> =
        crate::mirrors::distinct_by_host(mirrors.iter().map(|data| &data.mirror))
            .into_iter()
            // Guaranteed present by `distinct_by_host`; the `filter_map` only
            // satisfies the type of `host_str`.
            .filter_map(|mirror| mirror.url.host_str().map(str::to_owned))
            .collect();
    let lookups = hosts.len();
    let resolved: HashSet<_> = futures_util::stream::iter(hosts)
        .map(|host| async move { resolver.warm(&host).await.then_some(host) })
        .buffer_unordered(resolver.lookup_concurrency())
        .filter_map(std::future::ready)
        .collect()
        .await;
    let mirrors: Vec<_> = mirrors
        .into_iter()
        .filter(|data| {
            data.mirror
                .url
                .host_str()
                .is_some_and(|host| resolved.contains(host))
        })
        .collect();
    let failures = resolver.take_failures();
    snafu::ensure_whatever!(
        !mirrors.is_empty(),
        "No mirror hostname resolved ({failures})"
    );
    tracing::info!("Name resolution kept {}/{total} mirrors", mirrors.len());
    // Against lookups, not mirrors: the tally holds one entry per distinct
    // failing host, so the lookup count is the denominator that keeps the
    // ratio honest — the convention the survey already reports against.
    failures.warn_if_resolver_bound(lookups);
    Ok(mirrors)
}

/// Phase 2a: probes every mirror's `lastsync` URL for
/// [`LATENCY_PHASE_DURATION`], recording per-probe latency (or errors)
/// into each mirror's [`PingStatRunning`].
pub(crate) async fn latency_phase(
    client: &reqwest::Client,
    mut mirrors: Vec<MirrorData<PingStatRunning>>,
) -> Vec<MirrorData<PingStatRunning>> {
    // Deadline shared by every ping stream and by each individual request
    // (see `ping_url` for the per-request timeout).
    //
    // Follow-up, deliberately not done yet: every stream fires its first —
    // cold — probe at the same instant, so a large country opens on the order
    // of a hundred TLS handshakes at once and they contend for CPU. Cold
    // samples no longer feed the ranking statistics, so today this only
    // pollutes the setup figures; if those ever start to matter, stagger the
    // first probes across `[0, interval)` — that spreads the burst without
    // costing wall time.
    let deadline = Instant::now() + LATENCY_PHASE_DURATION;
    let streams = mirrors
        .iter()
        .enumerate()
        .map(|(n, mirror_data)| {
            crate::ping_test::ping_url(
                client,
                mirror_data.last_sync_url.clone(),
                PROBE_INTERVAL,
                deadline,
                // No adaptive cap here: all streams run concurrently under
                // one fixed deadline, so a hung request holds no scarce slot
                // and cutting it early would buy nothing.
                None,
                // No busting either: pacman's own requests would be served
                // by the same caches, so the cached path *is* the
                // user-visible latency this phase ranks by.
                crate::ping_test::CacheBust::Off,
            )
            .map(move |result| (n, result))
        })
        .map(Box::pin)
        .collect::<Vec<_>>();
    let mut pings = futures_util::stream::select_all(streams);
    while let Some((n, result)) = pings.next().await {
        let mirror_data = &mut mirrors[n];
        match result {
            Ok(probe) => {
                tracing::debug!(
                    "{}: {:?}{}",
                    mirror_data.mirror.url,
                    probe.latency,
                    if probe.cold { " (setup)" } else { "" },
                );
                mirror_data.ping_stat.record_ping(probe);
            }
            Err(err) => {
                tracing::debug!("{}: {err}", mirror_data.mirror.url);
            }
        }
    }
    mirrors
}

/// Phase 2b: turns raw ping samples into summary statistics, drops anything
/// slower than a 1s mean, then keeps the `ping_k` fastest survivors.
pub(crate) fn compute_and_filter_pings(
    mirrors: Vec<MirrorData<PingStatRunning>>,
    ping_k: NonZeroUsize,
) -> Result<Vec<MirrorData<PingStatComputed>>, snafu::Whatever> {
    // The setup-only policy itself is documented at the drop site, inside
    // the loop; `setup_only` is its provisional cost metric.
    let mut setup_only = 0usize;
    let mut kept = Vec::new();
    for data in mirrors {
        // Diagnosed before `compute_pings`, which consumes `data`: a mirror
        // whose only success was the cold probe is dropped outright rather
        // than judged by its handshake sample. The count above is a
        // provisional metric watching that policy's cost: if it stays high,
        // the alternative is to fall back to the setup sample for such
        // mirrors.
        if data.ping_stat.is_setup_only() {
            setup_only += 1;
            let setup = data
                .ping_stat
                .setup()
                .expect("setup-only implies a setup sample");
            tracing::debug!(
                "{}: dropped as setup-only, setup = {setup:.2?}",
                data.mirror.url
            );
            continue;
        }
        let Some(computed) = data.compute_pings() else {
            // No warm samples and no setup sample: a fully dead mirror, not
            // worth a log line of its own.
            continue;
        };
        // Anything slower than the acceptable mean is not worth the
        // download test.
        if computed.ping_stat.mean() <= MAX_ACCEPTABLE_MEAN {
            kept.push(computed);
        }
    }
    snafu::ensure_whatever!(!kept.is_empty(), "No servers to continue with");
    kept.sort_by_key(|m| m.ping_stat.mean());
    kept.truncate(ping_k.get());
    tracing::info!(
        "Latency phase finished, kept {} mirrors ({setup_only} dropped as setup-only)",
        kept.len()
    );
    if tracing::enabled!(tracing::Level::DEBUG) {
        for data in &kept {
            let mean = data.ping_stat.mean();
            let setup = data
                .ping_stat
                .setup()
                .map_or_else(|| "n/a".to_owned(), |s| format!("{s:.2?}"));
            tracing::debug!({ %data.mirror.url }, "mean = {mean:.2?}, setup = {setup}",);
        }
    }
    Ok(kept)
}

/// Phase 3a: measures throughput against each survivor, **serially**.
///
/// Running concurrent downloads would split local bandwidth between them
/// and distort the per-mirror measurement; that's why we don't parallelize.
pub(crate) async fn throughput_phase(
    client: &reqwest::Client,
    mut mirrors: Vec<MirrorData<PingStatComputed>>,
) -> Vec<MirrorData<PingStatComputed>> {
    let all_progress = MultiProgress::new();
    let mirrors_progress = all_progress.add(
        ProgressBar::new(mirrors.len() as u64).with_style(
            ProgressStyle::with_template(
                "Processing {pos:.cyan}/{len:.green} mirror {bar:20.cyan/blue} (elapsed {elapsed}, eta {eta})",
            )
            .expect("Template must be OK"),
        ),
    );
    let dl_progress = all_progress.add(
        ProgressBar::new_spinner().with_style(
            ProgressStyle::with_template(
                "{prefix:.cyan}: {elapsed} ({bytes}/{total_bytes}): {bytes_per_sec:.green}",
            )
            .expect("Must be OK"),
        ),
    );
    for data in &mut mirrors {
        mirrors_progress.inc(1);
        match dl_mirror(client, data, &dl_progress).await {
            Ok(speed) => data.dl_speed = Some(speed),
            Err(e) => tracing::warn!("{}: {}", data.mirror.url, DisplayErrorChain::new(&e)),
        }
    }
    mirrors_progress.finish_and_clear();
    dl_progress.finish_and_clear();
    drop(all_progress);
    mirrors
}

/// Phase 3b: drops mirrors whose download failed, ranks the rest fastest
/// first, and keeps the top `dl_k`.
pub(crate) fn rank_by_throughput(
    mirrors: Vec<MirrorData<PingStatComputed>>,
    dl_k: NonZeroUsize,
) -> Result<Vec<MirrorData<PingStatComputed, f64>>, snafu::Whatever> {
    let mut mirrors = mirrors
        .into_iter()
        .filter_map(MirrorData::into_measured)
        .collect::<Vec<_>>();
    snafu::ensure_whatever!(!mirrors.is_empty(), "No servers to continue with");
    mirrors.sort_by(|a, b| a.dl_speed.total_cmp(&b.dl_speed).reverse());
    mirrors.truncate(dl_k.get());
    tracing::info!("DL speed phase finished, kept {} mirrors", mirrors.len());
    Ok(mirrors)
}

/// Prints a one-per-mirror summary of the ranked survivors to stderr.
pub(crate) fn print_summary(mirrors: &[MirrorData<PingStatComputed, f64>]) {
    for data in mirrors {
        eprintln!(
            "{}:\n  * DL speed: {}\n  * Mean latency: {:.2?}",
            data.mirror.url,
            data.dl_speed.human_throughput_bytes(),
            data.ping_stat.mean()
        );
    }
}

/// Measures the download throughput of a single mirror.
///
/// First resolves the largest package via
/// [`crate::largest_file_discovery::discover`] — which itself downloads and
/// parses `core.db` — then downloads that package for up to two seconds and
/// returns the observed bytes-per-second.
pub(crate) async fn dl_mirror<T>(
    client: &reqwest::Client,
    mirror_data: &MirrorData<T>,
    dl_progress: &ProgressBar,
) -> Result<f64, snafu::Whatever> {
    /// One budget for the whole per-mirror throughput measurement: the
    /// `core.db` discovery request, the wait for the package's response
    /// headers, and the body download window each get these 2 seconds.
    ///
    /// Long enough for the largest package's bytes to make a 2s sample of
    /// the link meaningful, short enough that the serial phase across all
    /// survivors stays bounded no matter how many of them stall.
    const TIME_LIMIT: Duration = Duration::from_secs(2);

    let largest_file_url =
        crate::largest_file_discovery::discover(client, &mirror_data.mirror.url, TIME_LIMIT)
            .await
            .whatever_context("Failed to discover the largest file")?;
    dl_progress.set_prefix(mirror_data.mirror.url.to_string());
    dl_progress.reset();
    let result = crate::dl_test::download(
        client,
        largest_file_url.clone(),
        |downloaded, maybe_length| {
            if let Some(length) = maybe_length {
                dl_progress.set_length(length);
            }
            dl_progress.set_position(downloaded);
        },
        TIME_LIMIT,
    )
    .await;
    dl_progress.reset();
    let (bytes, time) = result.with_whatever_context(|_| {
        format!("Failed to download the largest file {largest_file_url}")
    })?;
    let speed = bytes as f64 / time.as_secs_f64();
    tracing::debug!(
        "{}: {bytes} bytes in {time:.2?}, speed = {:.2} KB/s",
        largest_file_url,
        speed / 1024.
    );
    Ok(speed)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mirrors::Protocol;
    use crate::ping_test::Probe;

    /// A well-formed HTTPS mirror with a distinct, sortable host name.
    fn mirror(n: usize) -> Mirror {
        Mirror {
            url: format!("https://mirror-{n}.example.com/archlinux/")
                .parse()
                .expect("test mirror URL must parse"),
            protocol: Protocol::Https,
            country_code: CountryCode::DE,
            delay: Some(60),
            last_sync: Some(time::OffsetDateTime::now_utc()),
        }
    }

    /// A pipeline entry with `setup_ms` cold and `warm_ms` warm samples
    /// recorded, exactly as `latency_phase` would have left it.
    fn running(n: usize, warm_ms: &[u64], setup_ms: Option<u64>) -> MirrorData<PingStatRunning> {
        let mut data = MirrorData::try_new(mirror(n)).expect("lastsync join must succeed");
        if let Some(setup) = setup_ms {
            data.ping_stat.record_ping(Probe {
                latency: Duration::from_millis(setup),
                cold: true,
            });
        }
        for ms in warm_ms {
            data.ping_stat.record_ping(Probe {
                latency: Duration::from_millis(*ms),
                cold: false,
            });
        }
        data
    }

    /// The same entry after `compute_pings` — with uniform warm samples the
    /// mean is the sample value, so callers can assert exact latencies.
    fn computed(n: usize, warm_ms: &[u64]) -> MirrorData<PingStatComputed> {
        running(n, warm_ms, Some(50))
            .compute_pings()
            .expect("warm samples must compute")
    }

    fn ping_k(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).expect("nonzero")
    }

    /// A mirror whose only success was the cold probe is dropped outright,
    /// not judged by its handshake sample.
    #[test]
    fn setup_only_mirrors_are_dropped() {
        let mirrors = vec![
            running(0, &[100, 110, 120], Some(900)),
            running(1, &[], Some(400)),
        ];
        let kept = compute_and_filter_pings(mirrors, ping_k(10)).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(
            kept[0].mirror.url.as_str(),
            "https://mirror-0.example.com/archlinux/"
        );
        // The surviving one is the warm one, despite the slower setup.
        assert_eq!(kept[0].ping_stat.mean(), Duration::from_millis(110));
    }

    /// A mean above `MAX_ACCEPTABLE_MEAN` disqualifies the mirror from the
    /// throughput phase.
    #[test]
    fn slow_means_are_dropped() {
        let mirrors = vec![running(0, &[1500, 1500], Some(400))];
        assert!(compute_and_filter_pings(mirrors, ping_k(10)).is_err());
    }

    /// `ping_k` keeps the fastest survivors, sorted by mean ascending.
    #[test]
    fn ping_k_truncates_to_the_fastest_in_mean_order() {
        let mirrors = vec![
            running(0, &[300, 300], Some(400)),
            running(1, &[100, 100], Some(400)),
            running(2, &[200, 200], Some(400)),
        ];
        let kept = compute_and_filter_pings(mirrors, ping_k(2)).unwrap();
        let means: Vec<Duration> = kept.iter().map(|m| m.ping_stat.mean()).collect();
        assert_eq!(
            means,
            [Duration::from_millis(100), Duration::from_millis(200)]
        );
    }

    /// No warm samples anywhere means nothing to continue with.
    #[test]
    fn all_setup_only_is_an_error() {
        let mirrors = vec![running(0, &[], Some(400)), running(1, &[], None)];
        assert!(compute_and_filter_pings(mirrors, ping_k(10)).is_err());
    }

    /// Mirrors that failed the download measurement are filtered, not
    /// ranked.
    #[test]
    fn unmeasured_mirrors_are_dropped() {
        let mut fast = computed(0, &[100, 100]);
        fast.dl_speed = Some(50.0);
        let mut failed = computed(1, &[200, 200]);
        failed.dl_speed = None;
        let ranked = rank_by_throughput(vec![failed, fast], ping_k(10)).unwrap();
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].dl_speed, 50.0);
    }

    /// Ranking is descending, and equal speeds keep their input order
    /// (stable sort under `total_cmp`).
    #[test]
    fn ranking_is_descending_and_stable() {
        let mut a = computed(0, &[100, 100]);
        a.dl_speed = Some(30.0);
        let mut b = computed(1, &[200, 200]);
        b.dl_speed = Some(50.0);
        let mut c = computed(2, &[300, 300]);
        c.dl_speed = Some(30.0);
        let mut d = computed(3, &[400, 400]);
        d.dl_speed = Some(10.0);
        let ranked = rank_by_throughput(vec![a, b, c, d], ping_k(10)).unwrap();
        let order: Vec<&str> = ranked
            .iter()
            .map(|m| m.mirror.url.host_str().expect("host"))
            .collect();
        assert_eq!(
            order,
            [
                "mirror-1.example.com",
                "mirror-0.example.com",
                "mirror-2.example.com",
                "mirror-3.example.com",
            ]
        );
    }

    /// `dl_k` truncates the ranked list from the top.
    #[test]
    fn dl_k_truncates() {
        let mut a = computed(0, &[100, 100]);
        a.dl_speed = Some(10.0);
        let mut b = computed(1, &[200, 200]);
        b.dl_speed = Some(50.0);
        let mut c = computed(2, &[300, 300]);
        c.dl_speed = Some(30.0);
        let ranked = rank_by_throughput(vec![a, b, c], ping_k(2)).unwrap();
        assert_eq!(
            ranked.iter().map(|m| m.dl_speed as i64).collect::<Vec<_>>(),
            [50, 30]
        );
    }

    /// Every download having failed means nothing to write to the
    /// mirrorlist.
    #[test]
    fn all_unmeasured_is_an_error() {
        let mut a = computed(0, &[100, 100]);
        a.dl_speed = None;
        let mut b = computed(1, &[200, 200]);
        b.dl_speed = None;
        assert!(rank_by_throughput(vec![a, b], ping_k(10)).is_err());
    }
}
