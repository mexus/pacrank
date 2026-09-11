//! Auto-detect the user's nearest country (or top-K nearest countries) by
//! sample-pinging the global Archlinux mirror list.
//!
//! Runs in the user-context parent before any privilege escalation, so the
//! cache file lives under the invoking user's `XDG_CACHE_HOME` (not root's).
//! The result is a closed-set list of [`CountryCode`]s that the existing
//! discovery pipeline filters by.

use std::{
    collections::HashSet,
    fs,
    net::IpAddr,
    num::NonZeroUsize,
    path::PathBuf,
    time::{Duration, Instant},
};

use display_error_chain::DisplayErrorChain;
use futures_util::StreamExt;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use snafu::{ResultExt, Snafu};
use time::OffsetDateTime;

use crate::{
    CountryCode, Mirrors,
    dns::SurveyResolver,
    ping_test::{AdaptiveTimeout, CacheBust},
};

/// Maximum number of mirrors *pinged* concurrently during the survey.
///
/// Too high and TLS handshakes contend for CPU, distorting every measurement.
/// 16 keeps the numbers honest. Name resolution has no such constraint and
/// runs at its own, much wider limit — see
/// [`SurveyResolver::lookup_concurrency`].
const SURVEY_CONCURRENCY: usize = 16;

/// Per-mirror probe budget.
///
/// Sized by the only question the survey answers: is this country within
/// `threshold` (1.5x) of the baseline? That needs a rough median, not a
/// precise one — precision is the main pipeline's job, on the ~50 mirrors that
/// survive this screen.
///
/// At [`SURVEY_INTERVAL`] a *nearby* mirror fits four probes in here: the
/// cold one that pays TCP connect and the TLS handshake — set aside as the
/// setup figure — and roughly three warm ones that reuse the pooled
/// connection and form the median. Those are exactly the mirrors whose
/// numbers decide anything. A distant mirror fits fewer, so its median rests
/// on one or two warm samples; rough, but no longer inflated by the handshake
/// the way it was when cold and warm samples were pooled.
///
/// Shortening the budget therefore costs coverage rather than accuracy: a
/// mirror must land at least one warm sample or it is dropped as setup-only.
const SURVEY_BUDGET: Duration = Duration::from_millis(500);

/// Interval between probes against the same mirror (jittered ±10% inside
/// `ping_url`).
///
/// The main pipeline spaces probes a second apart to sample across time. A
/// country screen has no use for that spread, and paying for it cost ~2s per
/// mirror where ~0.5s buys the same verdict.
const SURVEY_INTERVAL: Duration = Duration::from_millis(150);

/// Starting (and maximum) value of the adaptive cold-probe cap.
///
/// Matches the worst case a request could take before the cap existed —
/// [`SURVEY_BUDGET`] plus `ping_test::DEADLINE_GRACE` (the per-request
/// grace inside `ping_url`) — so until the first setup samples arrive,
/// behavior is identical to the fixed cap.
const SETUP_TIMEOUT_INITIAL: Duration = Duration::from_secs(1);

/// The tightest the adaptive cold-probe cap may get.
///
/// A cold answer must land by [`SURVEY_BUDGET`] − [`SURVEY_INTERVAL`]
/// (~350ms, ±jitter) for a warm probe to still be scheduled; any later and
/// the mirror is dropped as setup-only regardless of what it said. 400ms
/// sits above that line, so however hard nearby samples pull the mean down,
/// the cap cannot censor a mirror that could still influence the verdict —
/// which is also why the cap's fast-mirror bias is safe to embrace.
const SETUP_TIMEOUT_FLOOR: Duration = Duration::from_millis(400);

/// Multiple of the warm median beyond which a mirror's connection setup
/// stops looking like a direct TCP + TLS handshake.
///
/// A direct mirror's cold probe costs ~3–4× its round-trip (TCP, TLS, then
/// the request) plus a few ms of crypto; observed honest mirrors sit at
/// 2–2.5×. A ratio past 5 means TLS terminated somewhere much closer than
/// the machine that actually answers — a CDN/anycast edge — and the warm
/// median then measures the edge (or its cache), not the mirror, e.g.
/// `mirror.krfoss.org`: Cloudflare-fronted, labelled KR, 6.8× from here.
const CDN_SUSPECT_RATIO: u32 = 5;

/// Below this setup time the ratio test is meaningless: for very near
/// mirrors the fixed costs (TLS crypto, server work) dominate the setup, so
/// a perfectly direct 3ms-median mirror can post a ratio of 8. No CDN
/// verdict is worth making under 100ms of setup.
const CDN_SUSPECT_SETUP_FLOOR: Duration = Duration::from_millis(100);

/// Cached countries are considered fresh for this long even when the public
/// IP /16 still matches; after this we re-detect to catch shifts in the
/// mirror network (mirrors going dark, new ones coming online).
const CACHE_TTL: Duration = Duration::from_secs(60 * 60 * 24 * 30);

/// Public-IP discovery endpoints, tried in order. First success wins.
const IP_ENDPOINTS: &[IpEndpoint] = &[
    IpEndpoint {
        url: "https://www.cloudflare.com/cdn-cgi/trace",
        parser: parse_cloudflare_trace,
    },
    IpEndpoint {
        url: "https://ifconfig.co/ip",
        parser: parse_plain_ip,
    },
    IpEndpoint {
        url: "https://api.ipify.org",
        parser: parse_plain_ip,
    },
];

struct IpEndpoint {
    url: &'static str,
    parser: fn(&str) -> Option<IpAddr>,
}

/// Tunables for [`resolve`].
#[derive(Debug, Clone, Copy)]
pub struct DetectOptions {
    /// Number of fastest-pinged mirrors whose median latency forms the
    /// per-mirror baseline.
    pub baseline_n: NonZeroUsize,
    /// Mirrors whose latency is greater than `threshold * baseline` are
    /// dropped before country selection.
    pub threshold: f64,
    /// Maximum number of distinct countries returned.
    pub k_countries: NonZeroUsize,
    /// If `false`, ignore any existing cache entry and always survey.
    pub read_cache: bool,
    /// If `false`, do not persist freshly-detected countries to disk.
    /// Decoupled from [`Self::read_cache`] so `--dry-run` can still read the
    /// cache (mirroring a real run's fast path) without leaving side effects.
    pub write_cache: bool,
}

/// Errors that abort country detection.
///
/// Cache misses and partial network failures are handled internally and do
/// not surface as errors — they fall back to either re-detection or a stale
/// cache as appropriate, unless `DetectError::is_fatal` says otherwise.
#[derive(Debug, Snafu)]
pub enum DetectError {
    /// Building the HTTP client failed.
    BuildClient { source: reqwest::Error },
    /// Fetching the global mirrors list failed.
    FetchMirrors { source: reqwest::Error },
    /// Parsing the global mirrors list failed.
    ParseMirrors { source: reqwest::Error },
    /// Constructing a Tokio runtime failed.
    BuildRuntime { source: std::io::Error },
    /// All public-IP endpoints failed AND no usable cache existed to fall
    /// back on.
    NoIpAndNoCache,
    /// Survey produced no usable samples and there is no cache to fall back
    /// on (e.g. offline first run).
    NoSamplesAndNoCache,
    /// After applying the latency threshold, no mirror survived; on a real
    /// machine this means every mirror is unreachable.
    NoCountriesSelected,
}

impl DetectError {
    /// Whether this failure also dooms the run that follows detection.
    ///
    /// The list surveyed here is the very same document the download phase
    /// filters, so once it can't be fetched or parsed there is nothing a
    /// cached country list can rescue: the run would get as far as the sudo
    /// password prompt and then fail identically. Better to surface the real
    /// cause immediately, while the user still has context for it.
    ///
    /// Failures specific to detection itself are not fatal — an unreachable
    /// survey says nothing about whether the download phase will work, so a
    /// stale cache remains a reasonable guess there.
    fn is_fatal(&self) -> bool {
        // Matched exhaustively on purpose: a new variant should not silently
        // inherit either answer.
        match self {
            Self::FetchMirrors { .. }
            | Self::ParseMirrors { .. }
            // Neither of these can reach the fallback (both are raised before
            // it), but the pipeline reconstructs the same client and runtime,
            // so a cache could not save them either.
            | Self::BuildClient { .. }
            | Self::BuildRuntime { .. } => true,
            Self::NoIpAndNoCache | Self::NoSamplesAndNoCache | Self::NoCountriesSelected => false,
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct CacheEntry {
    /// Public IP masked to /16 (v4) or /48 (v6) — coarse enough to survive
    /// CGNAT churn but tight enough to catch laptop-on-new-network.
    ip_prefix: String,
    #[serde(with = "time::serde::iso8601")]
    detected_at: OffsetDateTime,
    countries: Vec<CountryCode>,
}

/// Synchronous entry point. Builds a small Tokio runtime internally so
/// callers don't need to care about async; intended to run in the
/// user-context parent before any privilege escalation.
pub fn resolve(opts: DetectOptions) -> Result<Vec<CountryCode>, DetectError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context(BuildRuntimeSnafu)?;
    let result = rt.block_on(resolve_async(opts));
    // Never a plain `drop(rt)` — see `dns::SHUTDOWN_GRACE`.
    rt.shutdown_timeout(crate::dns::SHUTDOWN_GRACE);
    result
}

async fn resolve_async(opts: DetectOptions) -> Result<Vec<CountryCode>, DetectError> {
    // The survey warms this resolver ahead of the pings; handing the same
    // instance to reqwest is what turns those warm-ups into cache hits.
    let resolver = SurveyResolver::new();
    let client = crate::build_client(resolver.clone()).context(BuildClientSnafu)?;

    let cache_file = if opts.read_cache || opts.write_cache {
        cache_path()
    } else {
        None
    };
    let cached = if opts.read_cache {
        cache_file.as_deref().and_then(load_cache)
    } else {
        None
    };

    if opts.read_cache
        && let Some(entry) = cached.as_ref()
        && let Some(prefix) = current_ip_prefix(&client).await
        && prefix == entry.ip_prefix
        && fresh_enough(entry)
    {
        tracing::info!(
            "Using cached countries: {} — IP prefix matches and cache is fresh.",
            CountryCode::format_list(&entry.countries)
        );
        return Ok(entry.countries.clone());
    }

    match detect(&client, &resolver, opts).await {
        Ok(countries) => {
            if opts.write_cache
                && let Some(path) = cache_file
            {
                let prefix = current_ip_prefix(&client).await;
                if let Some(prefix) = prefix {
                    let entry = CacheEntry {
                        ip_prefix: prefix,
                        detected_at: OffsetDateTime::now_utc(),
                        countries: countries.clone(),
                    };
                    if let Err(e) = save_cache(&path, &entry) {
                        tracing::warn!(
                            "Failed to save country cache to {}: {}",
                            path.display(),
                            DisplayErrorChain::new(&*e)
                        );
                    }
                } else {
                    tracing::warn!(
                        "Could not determine public IP prefix; not writing country cache."
                    );
                }
            }
            Ok(countries)
        }
        Err(detect_err) => match cached {
            Some(entry) if !detect_err.is_fatal() => {
                tracing::warn!(
                    "Country detection failed ({}); falling back to stale cache: {}",
                    DisplayErrorChain::new(&detect_err),
                    CountryCode::format_list(&entry.countries),
                );
                Ok(entry.countries)
            }
            _ => Err(detect_err),
        },
    }
}

fn fresh_enough(entry: &CacheEntry) -> bool {
    let age = OffsetDateTime::now_utc() - entry.detected_at;
    let Ok(age) = Duration::try_from(age) else {
        // Negative age (clock skew) — treat as fresh rather than re-detect.
        return true;
    };
    age <= CACHE_TTL
}

async fn detect(
    client: &reqwest::Client,
    resolver: &SurveyResolver,
    opts: DetectOptions,
) -> Result<Vec<CountryCode>, DetectError> {
    let samples = survey(client, resolver).await?;
    if samples.is_empty() {
        return Err(DetectError::NoSamplesAndNoCache);
    }
    let countries = select_countries(samples, opts);
    if countries.is_empty() {
        return Err(DetectError::NoCountriesSelected);
    }
    tracing::info!(
        "Detected {} closest countries: {}",
        countries.len(),
        CountryCode::format_list(&countries)
    );
    Ok(countries)
}

/// One ping sample summary per mirror.
struct Sample {
    country: CountryCode,
    median: Duration,
}

async fn survey(
    client: &reqwest::Client,
    resolver: &SurveyResolver,
) -> Result<Vec<Sample>, DetectError> {
    let Mirrors::V3(mirrors) = client
        .get("https://archlinux.org/mirrors/status/json/")
        .send()
        .await
        .context(FetchMirrorsSnafu)?
        .json()
        .await
        .context(ParseMirrorsSnafu)?;

    let max_delay = Duration::from_hours(48);
    let oldest_sync = OffsetDateTime::now_utc() - max_delay;
    // One entry per host. `http://X` and `https://X` are two mirrors but one
    // machine in one country, so probing both answers the same question twice;
    // dropping the duplicates takes ~805 entries down to ~487 for free.
    let mut seen_hosts = HashSet::new();
    let candidates: Vec<_> = mirrors
        .urls
        .into_iter()
        .filter(|m| {
            m.is_http()
                && m.country_code != CountryCode::Unknown
                && m.last_sync.is_some_and(|ts| ts >= oldest_sync)
                && m.delay.is_some_and(|d| d <= max_delay.as_secs() as i64)
        })
        .filter_map(|m| {
            let host = m.url.host_str()?.to_owned();
            let url = m.url.join("lastsync").ok()?;
            Some((m.country_code, url, host))
        })
        .filter(|(_, _, host)| seen_hosts.insert(host.clone()))
        .collect();

    let candidate_count = candidates.len();
    tracing::info!(
        "Auto-detecting closest countries by probing {candidate_count} mirrors ({} lookups, {} \
         pings in flight).",
        resolver.lookup_concurrency(),
        SURVEY_CONCURRENCY,
    );

    // Progress UI: an ETA bar over resolution — every candidate passes through
    // it, so it doubles as overall progress — plus a live leaderboard of the
    // closest countries seen so far. Both clear on finish; the surrounding
    // `tracing::info!` calls are the durable log record.
    let progress = MultiProgress::new();
    let resolve_bar = progress.add(
        ProgressBar::new(candidates.len() as u64).with_style(
            ProgressStyle::with_template(
                "  Resolved {pos:.cyan}/{len:.green} {bar:30.cyan/blue} \
                 (elapsed {elapsed}, eta {eta})",
            )
            .expect("Template must be OK"),
        ),
    );
    resolve_bar.enable_steady_tick(Duration::from_millis(120));
    let leaders_bar = progress.add(
        ProgressBar::new_spinner().with_style(
            ProgressStyle::with_template("  Pinged {pos:.cyan} · closest so far: {msg}")
                .expect("Template must be OK"),
        ),
    );
    leaders_bar.enable_steady_tick(Duration::from_millis(120));
    leaders_bar.set_message("(awaiting first samples)");

    // One cap shared by every cold probe of this run: each setup sample
    // tightens it, so hopeless mirrors release their survey slot sooner as
    // the run learns the local latency landscape.
    let setup_timeout = AdaptiveTimeout::new(SETUP_TIMEOUT_INITIAL, SETUP_TIMEOUT_FLOOR);

    // Two stages, two widths, no barrier between them: a mirror enters the
    // ping stage the moment *its own* name resolves. `buffer_unordered` also
    // supplies the backpressure — resolution runs at most one buffer ahead of
    // pinging and then waits, so a fast DNS server cannot run away with the
    // whole list.
    let pings = futures_util::stream::iter(candidates)
        .map(|(country, url, host)| {
            let resolver = resolver.clone();
            let resolve_bar = resolve_bar.clone();
            async move {
                let resolved = resolver.warm(&host).await;
                resolve_bar.inc(1);
                // A name that will not resolve costs one lookup here instead
                // of a whole ping budget downstream.
                resolved.then_some((country, url, host))
            }
        })
        .buffer_unordered(resolver.lookup_concurrency())
        .filter_map(std::future::ready)
        .map(|(country, url, host)| {
            let client = client.clone();
            let setup_timeout = setup_timeout.clone();
            async move { (country, host, probe(&client, url, setup_timeout).await) }
        })
        .buffer_unordered(SURVEY_CONCURRENCY);
    futures_util::pin_mut!(pings);

    let mut results = Vec::new();
    let mut setup_only = 0usize;
    let mut leaders: Vec<(CountryCode, Duration)> = Vec::new();
    while let Some((country, host, (setup, mut warm))) = pings.next().await {
        leaders_bar.inc(1);
        if warm.is_empty() {
            // Same policy as the main pipeline: a mirror whose only answer
            // was the cold probe is dropped, not judged by its handshake.
            // Counted so the policy's cost stays visible.
            if let Some(setup) = setup {
                setup_only += 1;
                tracing::debug!(
                    "{} {host}: dropped as setup-only, setup {setup:.2?}",
                    country.as_code()
                );
            }
            continue;
        }
        warm.sort_unstable();
        let median = warm[warm.len() / 2];
        // Log-only canary. Cache-busted probes should make a CDN front
        // measure as far, so this firing means some cache answered busted
        // URLs anyway — worth knowing, but the mirror keeps its vote.
        if let Some(setup) = setup
            && is_cdn_suspect(setup, median)
        {
            tracing::info!(
                "{} {host}: setup {setup:.2?} is {:.1}x its warm median {median:.2?} — likely a \
                 CDN/anycast front; its country evidence may be misleading.",
                country.as_code(),
                setup.as_secs_f64() / median.as_secs_f64(),
            );
        }
        // The per-mirror record behind a country verdict. Cheap to emit and
        // the only way to tell a genuinely close mirror from a mislabelled or
        // misbehaving one after the fact.
        let setup = setup.map_or_else(|| "n/a".to_owned(), |s| format!("{s:.2?}"));
        tracing::debug!(
            "{} {host}: median {median:.2?} of {warm:.2?}, setup {setup}",
            country.as_code()
        );
        update_leaders(&mut leaders, country, median);
        leaders_bar.set_message(format_leaders(&leaders));
        results.push(Sample { country, median });
    }
    resolve_bar.finish_and_clear();
    leaders_bar.finish_and_clear();
    drop(progress);

    // After the bars are gone, so the warning is not painted over — and after
    // the stream is drained, since resolution here is interleaved with the
    // pings rather than finished up front.
    resolver
        .take_failures()
        .warn_if_resolver_bound(candidate_count);

    if setup_only > 0 {
        tracing::info!(
            "{setup_only} mirrors dropped as setup-only (only the cold probe answered)."
        );
    }
    tracing::debug!(
        "Adaptive cold-probe cap settled at {:.2?} after cutting {} probes.",
        setup_timeout.current(),
        setup_timeout.timeouts(),
    );
    Ok(results)
}

/// Probes one mirror for [`SURVEY_BUDGET`] and returns its connection-setup
/// latency (the cold probe) plus the raw warm samples.
///
/// The name is already in the resolver's cache by the time this runs, so the
/// cold probe pays connect and TLS but never DNS.
///
/// Probes are cache-busted: an edge cache must traverse to the origin for
/// every sample, so a CDN front cannot masquerade as a near mirror by
/// answering from a nearby cache (the `mirror.krfoss.org` case). Direct
/// mirrors serve the same file either way.
async fn probe(
    client: &reqwest::Client,
    url: url::Url,
    setup_timeout: AdaptiveTimeout,
) -> (Option<Duration>, Vec<Duration>) {
    let deadline = Instant::now() + SURVEY_BUDGET;
    let stream = crate::ping_test::ping_url(
        client,
        url,
        SURVEY_INTERVAL,
        deadline,
        Some(setup_timeout),
        CacheBust::PerProbe,
    );
    futures_util::pin_mut!(stream);
    let mut setup = None;
    let mut warm = Vec::new();
    while let Some(result) = stream.next().await {
        if let Ok(probe) = result {
            if probe.cold {
                setup.get_or_insert(probe.latency);
            } else {
                warm.push(probe.latency);
            }
        }
    }
    (setup, warm)
}

/// Whether a mirror's setup/median relationship betrays a CDN or anycast
/// front rather than a direct connection — see [`CDN_SUSPECT_RATIO`] and
/// [`CDN_SUSPECT_SETUP_FLOOR`] for the two thresholds and their rationale.
fn is_cdn_suspect(setup: Duration, median: Duration) -> bool {
    setup > CDN_SUSPECT_SETUP_FLOOR && setup > median * CDN_SUSPECT_RATIO
}

/// Maintains an in-place top-3 leaderboard keyed on best-seen median per
/// country. Called once per survey result; cheap because the vec stays at
/// length ≤ 3.
fn update_leaders(
    leaders: &mut Vec<(CountryCode, Duration)>,
    country: CountryCode,
    median: Duration,
) {
    if let Some(slot) = leaders.iter_mut().find(|(c, _)| *c == country) {
        if median >= slot.1 {
            return;
        }
        slot.1 = median;
    } else {
        leaders.push((country, median));
    }
    leaders.sort_by_key(|&(_, m)| m);
    leaders.truncate(3);
}

/// Renders the live leaderboard for the survey's progress bar.
///
/// Short codes here, unlike everywhere else: the bar is redrawn in place and
/// indicatif truncates it to the terminal width, which three spelled-out
/// names (`United Arab Emirates 123.45ms · …`) would blow past.
fn format_leaders(leaders: &[(CountryCode, Duration)]) -> String {
    leaders
        .iter()
        .map(|(c, m)| format!("{} {:.2?}", c.as_code(), m))
        .collect::<Vec<_>>()
        .join("  ·  ")
}

fn select_countries(mut samples: Vec<Sample>, opts: DetectOptions) -> Vec<CountryCode> {
    samples.sort_unstable_by_key(|s| s.median);

    let baseline_window = samples.len().min(opts.baseline_n.get());
    if baseline_window == 0 {
        return Vec::new();
    }
    let baseline = samples[baseline_window / 2].median;
    let cutoff = baseline.mul_f64(opts.threshold);
    tracing::debug!("Baseline {baseline:.2?} over {baseline_window} mirrors, cutoff {cutoff:.2?}",);

    let mut picked: Vec<CountryCode> = Vec::with_capacity(opts.k_countries.get());
    for s in samples {
        if s.median > cutoff {
            break;
        }
        if !picked.contains(&s.country) {
            picked.push(s.country);
            if picked.len() >= opts.k_countries.get() {
                break;
            }
        }
    }
    picked
}

// ---------- Public-IP fetch ----------

async fn current_ip_prefix(client: &reqwest::Client) -> Option<String> {
    for endpoint in IP_ENDPOINTS {
        match fetch_endpoint(client, endpoint).await {
            Some(ip) => return Some(mask_to_prefix(ip)),
            None => continue,
        }
    }
    None
}

async fn fetch_endpoint(client: &reqwest::Client, endpoint: &IpEndpoint) -> Option<IpAddr> {
    let fetch = client
        .get(endpoint.url)
        .timeout(Duration::from_secs(2))
        .send();
    let response = match fetch.await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(
                "IP endpoint {} failed: {}",
                endpoint.url,
                DisplayErrorChain::new(&e)
            );
            return None;
        }
    };
    if !response.status().is_success() {
        tracing::debug!(
            "IP endpoint {} returned {}",
            endpoint.url,
            response.status()
        );
        return None;
    }
    let body = match response.text().await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(
                "IP endpoint {} body read failed: {}",
                endpoint.url,
                DisplayErrorChain::new(&e)
            );
            return None;
        }
    };
    (endpoint.parser)(&body)
}

fn parse_cloudflare_trace(body: &str) -> Option<IpAddr> {
    body.lines()
        .find_map(|line| line.strip_prefix("ip="))
        .and_then(|s| s.trim().parse().ok())
}

fn parse_plain_ip(body: &str) -> Option<IpAddr> {
    body.trim().parse().ok()
}

fn mask_to_prefix(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            format!("{a}.{b}.0.0/16")
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", segs[0], segs[1], segs[2])
        }
    }
}

// ---------- Cache I/O ----------

fn cache_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME")
        && !xdg.is_empty()
    {
        return Some(PathBuf::from(xdg).join("pacrank").join("countries.json"));
    }
    let home = std::env::var("HOME").ok()?;
    if home.is_empty() {
        return None;
    }
    Some(
        PathBuf::from(home)
            .join(".cache")
            .join("pacrank")
            .join("countries.json"),
    )
}

fn load_cache(path: &std::path::Path) -> Option<CacheEntry> {
    let bytes = fs::read(path).ok()?;
    match serde_json::from_slice::<CacheEntry>(&bytes) {
        Ok(mut entry) => {
            // The file is user-writable and may have been produced by an
            // older version, so normalize on the way in — otherwise the
            // duplicates leak into both the log line and the pipeline.
            CountryCode::dedup(&mut entry.countries);
            Some(entry)
        }
        Err(e) => {
            tracing::warn!(
                "Failed to parse country cache at {}: {} — ignoring.",
                path.display(),
                e
            );
            None
        }
    }
}

fn save_cache(
    path: &std::path::Path,
    entry: &CacheEntry,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(entry)?;
    let tmp = tempfile::NamedTempFile::new_in(path.parent().unwrap_or(std::path::Path::new(".")))?;
    fs::write(tmp.path(), &bytes)?;
    tmp.persist(path)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use super::*;

    fn sample(country: CountryCode, ms: u64) -> Sample {
        Sample {
            country,
            median: Duration::from_millis(ms),
        }
    }

    fn opts(baseline_n: usize, k: usize, threshold: f64) -> DetectOptions {
        DetectOptions {
            baseline_n: NonZeroUsize::new(baseline_n).unwrap(),
            threshold,
            k_countries: NonZeroUsize::new(k).unwrap(),
            read_cache: false,
            write_cache: false,
        }
    }

    /// Builds a genuine [`reqwest::Error`] without touching the network: the
    /// URL fails to parse, and the failure is reported on `send`.
    async fn any_reqwest_error() -> reqwest::Error {
        reqwest::Client::new()
            .get("not a url")
            .send()
            .await
            .expect_err("An unparseable URL must fail")
    }

    /// A mirrors list we can't fetch or parse dooms the download phase too,
    /// so detection must not paper over it with a stale cache — otherwise the
    /// user types their sudo password only to hit the same error afterwards.
    #[tokio::test]
    async fn mirror_list_failures_are_fatal() {
        let fetch = DetectError::FetchMirrors {
            source: any_reqwest_error().await,
        };
        let parse = DetectError::ParseMirrors {
            source: any_reqwest_error().await,
        };
        assert!(fetch.is_fatal(), "{fetch:?}");
        assert!(parse.is_fatal(), "{parse:?}");
    }

    /// Detection-specific failures say nothing about the download phase, so
    /// these keep the stale-cache fallback.
    #[test]
    fn detection_failures_keep_the_cache_fallback() {
        for error in [
            DetectError::NoIpAndNoCache,
            DetectError::NoSamplesAndNoCache,
            DetectError::NoCountriesSelected,
        ] {
            assert!(!error.is_fatal(), "{error:?}");
        }
    }

    #[test]
    fn select_countries_happy_path() {
        let samples = vec![
            sample(CountryCode::DE, 10),
            sample(CountryCode::DE, 12),
            sample(CountryCode::NL, 15),
            sample(CountryCode::AT, 18),
            sample(CountryCode::FR, 20),
            sample(CountryCode::US, 200),
            sample(CountryCode::JP, 220),
        ];
        let picked = select_countries(samples, opts(5, 3, 1.5));
        assert_eq!(
            picked,
            vec![CountryCode::DE, CountryCode::NL, CountryCode::AT]
        );
    }

    #[test]
    fn select_countries_dedupes_same_country() {
        // Country with two fast mirrors should appear exactly once.
        let samples = vec![
            sample(CountryCode::DE, 10),
            sample(CountryCode::DE, 11),
            sample(CountryCode::DE, 12),
            sample(CountryCode::NL, 15),
        ];
        let picked = select_countries(samples, opts(3, 3, 1.5));
        // Threshold drops nothing here; we expect DE then NL, no duplicates.
        assert_eq!(picked, vec![CountryCode::DE, CountryCode::NL]);
    }

    #[test]
    fn select_countries_threshold_drops_far_mirrors() {
        let samples = vec![
            sample(CountryCode::DE, 10),
            sample(CountryCode::NL, 12),
            // 20ms baseline-median → 30ms cutoff at 1.5×; FR at 100ms is dropped.
            sample(CountryCode::FR, 100),
        ];
        let picked = select_countries(samples, opts(3, 3, 1.5));
        assert_eq!(picked, vec![CountryCode::DE, CountryCode::NL]);
    }

    #[test]
    fn select_countries_returns_what_survives_when_fewer_than_k() {
        // baseline_n=1 → baseline is the single fastest mirror; cutoff =
        // 1.5×10ms = 15ms, so FR at 500ms drops.
        let samples = vec![sample(CountryCode::DE, 10), sample(CountryCode::FR, 500)];
        let picked = select_countries(samples, opts(1, 5, 1.5));
        // Only DE is within threshold; we don't pad up to k.
        assert_eq!(picked, vec![CountryCode::DE]);
    }

    #[test]
    fn select_countries_empty_input() {
        let picked = select_countries(vec![], opts(5, 3, 1.5));
        assert!(picked.is_empty());
    }

    #[test]
    fn mask_v4_to_slash16() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        assert_eq!(mask_to_prefix(ip), "203.0.0.0/16");
    }

    #[test]
    fn mask_another_v4() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4));
        assert_eq!(mask_to_prefix(ip), "8.8.0.0/16");
    }

    #[test]
    fn mask_v6_to_slash48() {
        let ip: IpAddr = "2001:db8:abcd:1234::1".parse().unwrap();
        assert_eq!(mask_to_prefix(ip), "2001:db8:abcd::/48");
    }

    #[test]
    fn parse_cloudflare_trace_extracts_ip() {
        let body = "fl=12a34\nh=www.cloudflare.com\nip=203.0.113.42\nts=1700000000\n";
        let ip = parse_cloudflare_trace(body).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)));
    }

    #[test]
    fn parse_cloudflare_trace_missing_ip() {
        let body = "fl=12a34\nh=www.cloudflare.com\n";
        assert!(parse_cloudflare_trace(body).is_none());
    }

    #[test]
    fn parse_plain_ip_handles_trailing_newline() {
        let body = "203.0.113.42\n";
        let ip = parse_plain_ip(body).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)));
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn cdn_suspect_flags_edge_terminated_tls() {
        // The observed anomaly: mirror.krfoss.org, Cloudflare-fronted and
        // labelled KR, posted 130ms setup on a 19ms warm median (6.8x).
        assert!(is_cdn_suspect(ms(130), ms(19)));
    }

    #[test]
    fn cdn_suspect_spares_direct_mirrors() {
        // Honest ratios observed in the wild: ~2.3x and ~2x.
        assert!(!is_cdn_suspect(ms(41), ms(18)));
        assert!(!is_cdn_suspect(ms(88), ms(44)));
    }

    #[test]
    fn cdn_suspect_spares_near_mirrors_despite_high_ratio() {
        // 3ms median, 30ms setup: ratio 10, but fixed crypto costs dominate
        // at this range — the absolute floor keeps it trusted.
        assert!(!is_cdn_suspect(ms(30), ms(3)));
    }

    #[test]
    fn cdn_suspect_thresholds_are_strict() {
        // Exactly at the floor or exactly at the ratio: not suspect.
        assert!(!is_cdn_suspect(ms(100), ms(10)));
        assert!(!is_cdn_suspect(ms(500), ms(100)));
        assert!(is_cdn_suspect(ms(501), ms(100)));
    }

    #[test]
    fn leaders_keep_lowest_per_country_top3() {
        let mut leaders = Vec::new();
        update_leaders(&mut leaders, CountryCode::DE, Duration::from_millis(20));
        update_leaders(&mut leaders, CountryCode::NL, Duration::from_millis(15));
        // Same country, slower: must be ignored.
        update_leaders(&mut leaders, CountryCode::DE, Duration::from_millis(50));
        // Same country, faster: must replace.
        update_leaders(&mut leaders, CountryCode::DE, Duration::from_millis(10));
        update_leaders(&mut leaders, CountryCode::AT, Duration::from_millis(18));
        update_leaders(&mut leaders, CountryCode::FR, Duration::from_millis(12));
        // Five distinct countries seen, leaderboard caps at 3.
        assert_eq!(leaders.len(), 3);
        // Sorted ascending by median.
        assert_eq!(leaders[0].0, CountryCode::DE);
        assert_eq!(leaders[0].1, Duration::from_millis(10));
        assert_eq!(leaders[1].0, CountryCode::FR);
        assert_eq!(leaders[2].0, CountryCode::NL);
    }

    #[test]
    fn cache_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("countries.json");
        let entry = CacheEntry {
            ip_prefix: "203.0.0.0/16".to_string(),
            detected_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            countries: vec![CountryCode::DE, CountryCode::NL, CountryCode::AT],
        };
        save_cache(&path, &entry).unwrap();
        let loaded = load_cache(&path).unwrap();
        assert_eq!(loaded.ip_prefix, entry.ip_prefix);
        assert_eq!(loaded.detected_at, entry.detected_at);
        assert_eq!(loaded.countries, entry.countries);
    }

    /// A cache file written by an older version can carry repeats; loading
    /// must normalize them away.
    #[test]
    fn cache_load_dedupes_countries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("countries.json");
        let entry = CacheEntry {
            ip_prefix: "203.0.0.0/16".to_string(),
            detected_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            countries: vec![
                CountryCode::RU,
                CountryCode::CN,
                CountryCode::RU,
                CountryCode::CN,
            ],
        };
        save_cache(&path, &entry).unwrap();
        let loaded = load_cache(&path).unwrap();
        assert_eq!(
            loaded.countries,
            vec![CountryCode::RU, CountryCode::CN],
            "The load path must drop the duplicates"
        );
    }

    #[test]
    fn cache_load_missing_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        assert!(load_cache(&path).is_none());
    }

    #[test]
    fn cache_load_garbage_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage.json");
        fs::write(&path, b"this is not json").unwrap();
        assert!(load_cache(&path).is_none());
    }
}
