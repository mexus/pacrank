//! Auto-detect the user's nearest country (or top-K nearest countries) by
//! sample-pinging the global Archlinux mirror list.
//!
//! Runs in the user-context parent before any privilege escalation, so the
//! cache file lives under the invoking user's `XDG_CACHE_HOME` (not root's).
//! The result is a closed-set list of [`CountryCode`]s that the existing
//! discovery pipeline filters by.

use std::{
    fs,
    net::IpAddr,
    num::NonZeroUsize,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use display_error_chain::DisplayErrorChain;
use futures_util::{StreamExt, stream::FuturesUnordered};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use snafu::{ResultExt, Snafu};
use time::OffsetDateTime;
use tokio::sync::Semaphore;

use crate::{APP_USER_AGENT, CountryCode, Mirrors, Protocol};

/// Maximum number of mirrors probed concurrently during the survey.
///
/// Too high and the local link is saturated, distorting every measurement.
/// 16 leaves headroom on a residential connection while still finishing the
/// survey in reasonable wall time.
const SURVEY_CONCURRENCY: usize = 16;

/// Per-mirror probe budget. Matches the latency phase of the main pipeline.
const SURVEY_BUDGET: Duration = Duration::from_secs(3);

/// Interval between probes against the same mirror (jittered ±10% inside
/// `ping_url`).
const SURVEY_INTERVAL: Duration = Duration::from_secs(1);

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

/// Tunables for [`resolve`]. All fields have sensible defaults via
/// [`Self::default`].
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

impl Default for DetectOptions {
    fn default() -> Self {
        Self {
            baseline_n: NonZeroUsize::new(5).expect("5 != 0"),
            threshold: 1.5,
            k_countries: NonZeroUsize::new(3).expect("3 != 0"),
            read_cache: true,
            write_cache: true,
        }
    }
}

/// Errors that abort country detection.
///
/// Cache misses and partial network failures are handled internally and do
/// not surface as errors — they fall back to either re-detection or a stale
/// cache as appropriate.
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
    rt.block_on(resolve_async(opts))
}

async fn resolve_async(opts: DetectOptions) -> Result<Vec<CountryCode>, DetectError> {
    let client = reqwest::Client::builder()
        .user_agent(APP_USER_AGENT)
        .connect_timeout(Duration::from_secs(2))
        .tls_certs_only(crate::tls_roots())
        .build()
        .context(BuildClientSnafu)?;

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
            "Using cached countries ({}) — IP prefix matches and cache is fresh.",
            format_countries(&entry.countries)
        );
        return Ok(entry.countries.clone());
    }

    match detect(&client, opts).await {
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
        Err(detect_err) => {
            if let Some(entry) = cached {
                tracing::warn!(
                    "Country detection failed ({}); falling back to stale cache: {}",
                    DisplayErrorChain::new(&detect_err),
                    format_countries(&entry.countries),
                );
                Ok(entry.countries)
            } else {
                Err(detect_err)
            }
        }
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
    opts: DetectOptions,
) -> Result<Vec<CountryCode>, DetectError> {
    let samples = survey(client).await?;
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
        format_countries(&countries)
    );
    Ok(countries)
}

/// One ping sample summary per mirror.
struct Sample {
    country: CountryCode,
    median: Duration,
}

async fn survey(client: &reqwest::Client) -> Result<Vec<Sample>, DetectError> {
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
    let candidates: Vec<_> = mirrors
        .urls
        .into_iter()
        .filter(|m| {
            m.protocol != Protocol::Rsync
                && m.country_code != CountryCode::Unknown
                && m.last_sync.is_some_and(|ts| ts >= oldest_sync)
                && m.delay.is_some_and(|d| d <= max_delay.as_secs())
        })
        .filter_map(|m| {
            let url = m.url.join("lastsync").ok()?;
            Some((m.country_code, url))
        })
        .collect();

    tracing::info!(
        "Auto-detecting closest countries by probing {} mirrors (up to {} concurrent).",
        candidates.len(),
        SURVEY_CONCURRENCY,
    );

    let semaphore = Arc::new(Semaphore::new(SURVEY_CONCURRENCY));
    let mut futs = FuturesUnordered::new();
    for (country, url) in &candidates {
        let sem = Arc::clone(&semaphore);
        let client = client.clone();
        let country = *country;
        let url = url.clone();
        futs.push(async move {
            let _permit = sem
                .acquire_owned()
                .await
                .expect("Semaphore is never closed");
            let deadline = Instant::now() + SURVEY_BUDGET;
            let stream = crate::ping_test::ping_url(&client, url, SURVEY_INTERVAL, deadline);
            let mut samples: Vec<Duration> = Vec::new();
            futures_util::pin_mut!(stream);
            while let Some(result) = stream.next().await {
                if let Ok(d) = result {
                    samples.push(d);
                }
            }
            (country, samples)
        });
    }

    // Progress UI: a count/ETA bar plus a live leaderboard of the closest
    // countries seen so far. Both bars clear on finish; the surrounding
    // `tracing::info!` calls are the durable log record.
    let progress = MultiProgress::new();
    let bar = progress.add(
        ProgressBar::new(candidates.len() as u64).with_style(
            ProgressStyle::with_template(
                "  Surveyed {pos:.cyan}/{len:.green} {bar:30.cyan/blue} \
                 (elapsed {elapsed}, eta {eta})",
            )
            .expect("Template must be OK"),
        ),
    );
    bar.enable_steady_tick(Duration::from_millis(120));
    let leaders_bar = progress.add(ProgressBar::new_spinner().with_style(
        ProgressStyle::with_template("  Closest so far: {msg}").expect("Template must be OK"),
    ));
    leaders_bar.enable_steady_tick(Duration::from_millis(120));
    leaders_bar.set_message("(awaiting first samples)");

    let mut results = Vec::new();
    let mut leaders: Vec<(CountryCode, Duration)> = Vec::new();
    while let Some((country, mut samples)) = futs.next().await {
        bar.inc(1);
        if samples.is_empty() {
            continue;
        }
        samples.sort_unstable();
        let median = samples[samples.len() / 2];
        update_leaders(&mut leaders, country, median);
        leaders_bar.set_message(format_leaders(&leaders));
        results.push(Sample { country, median });
    }
    bar.finish_and_clear();
    leaders_bar.finish_and_clear();
    drop(progress);

    Ok(results)
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

fn format_countries(countries: &[CountryCode]) -> String {
    countries
        .iter()
        .map(CountryCode::as_code)
        .collect::<Vec<_>>()
        .join(", ")
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
        Ok(entry) => Some(entry),
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
