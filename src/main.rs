use std::{
    num::NonZeroUsize,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use arch_mirrors::{
    APP_USER_AGENT, CountryCode, Mirror, Mirrors, Protocol,
    ping_stat::{PingStatComputed, PingStatRunning},
};
use camino::Utf8Path;
use clap::Parser;
use display_error_chain::DisplayErrorChain;
use futures_util::StreamExt;
use human_repr::HumanThroughput;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use nonzero_ext::nonzero;
use rand::{Rng, SeedableRng};
use snafu::{OptionExt, ResultExt};
use time::OffsetDateTime;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;

/// Discover the fastest available Archlinux mirrors for the current location.
#[derive(Debug, Parser)]
struct Args {
    /// How many servers with the smallest ping to preserve.
    #[arg(long, default_value_t = nonzero!(10usize))]
    ping_k: NonZeroUsize,
    /// How many servers with the largest download speed to preserve.
    #[arg(long, default_value_t = nonzero!(5usize))]
    dl_k: NonZeroUsize,
    /// Whether to run the checks but don't save anything.
    #[arg(long, short)]
    dry_run: bool,

    /// Limit mirrors to these countries. Pass the flag multiple times for
    /// more than one (e.g. `-c US -c DE`).
    #[arg(long, short, value_enum, ignore_case = true, required = true)]
    country: Vec<CountryCode>,

    /// Runs a worker that drops privileges, discovers the fastest mirrors and
    /// reports them back.
    #[arg(long, hide(true))]
    worker: bool,
}

#[snafu::report]
fn main() -> Result<(), snafu::Whatever> {
    let Args {
        ping_k,
        dl_k,
        dry_run,
        worker,
        country,
    } = parse_args();

    init_tracing();

    // Three modes of operation:
    //   - dry-run:   drop to `nobody`, run the discovery, print results.
    //   - --worker:  same as dry-run but emits JSON to stdout for the parent.
    //   - default:   (re-)escalate to root, then spawn self with `--worker`,
    //                read its JSON stdout, and write `/etc/pacman.d/mirrorlist`.
    // The split keeps network I/O unprivileged while isolating the file
    // rewrite in a minimal privileged branch.
    if dry_run {
        run_dry_run(dl_k, ping_k, &country)
    } else if worker {
        run_worker(dl_k, ping_k, &country)
    } else {
        run_privileged()
    }
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
}

/// Parses CLI args, replacing clap's generic "required argument missing"
/// error with a list of accepted country codes.
///
/// `--country` is currently the only required argument, so any
/// `MissingRequiredArgument` here is about it; revisit if that ever changes.
fn parse_args() -> Args {
    match Args::try_parse() {
        Ok(args) => args,
        Err(e) if e.kind() == clap::error::ErrorKind::MissingRequiredArgument => {
            eprintln!(
                "error: at least one --country <COUNTRY> is required \
                 (repeat the flag for more than one). Accepted values:"
            );
            for cc in CountryCode::all() {
                eprintln!("  {}: {}", cc.as_code(), cc.full_name());
            }
            std::process::exit(2);
        }
        Err(e) => e.exit(),
    }
}

// ---------- Run modes ----------

/// Runs the full discovery pipeline without writing anything.
///
/// Drops to `nobody` only if invoked as root, so a non-privileged user can
/// still `--dry-run` without needing sudo.
fn run_dry_run(
    dl_k: NonZeroUsize,
    ping_k: NonZeroUsize,
    countries: &[CountryCode],
) -> Result<(), snafu::Whatever> {
    if nix::unistd::Uid::effective().is_root() {
        drop_privileges()?;
    }
    discover_best_mirrors(dl_k, ping_k, countries)?;
    tracing::info!("Refusing to update the mirror list (dry run enabled)");
    Ok(())
}

/// Unprivileged worker entry point: drops to `nobody`, runs discovery, and
/// emits the result as JSON on stdout for the parent to consume.
fn run_worker(
    dl_k: NonZeroUsize,
    ping_k: NonZeroUsize,
    countries: &[CountryCode],
) -> Result<(), snafu::Whatever> {
    drop_privileges()?;
    let result = discover_best_mirrors(dl_k, ping_k, countries)
        .map_err(|e| DisplayErrorChain::new(e).to_string());
    serde_json::to_writer(std::io::stdout(), &result)
        .whatever_context("Failed to serialize the result")?;
    Ok(())
}

/// Privileged parent entry point: make sure we're root, spawn an unprivileged
/// worker, and atomically replace `/etc/pacman.d/mirrorlist` with the result.
fn run_privileged() -> Result<(), snafu::Whatever> {
    escalate_if_needed()?;
    let mirrors = spawn_worker_and_read_mirrors()?;
    write_mirrorlist(&mirrors)?;
    Ok(())
}

// ---------- Privileged parent helpers ----------

/// Re-execs the process under sudo when the effective UID isn't root.
///
/// If escalation happens, this function does not return — it exits the
/// current process with the sudo child's exit code. On the already-root path
/// it simply returns `Ok(())`.
fn escalate_if_needed() -> Result<(), snafu::Whatever> {
    if nix::unistd::Uid::effective().is_root() {
        return Ok(());
    }
    // `ARCH_MIRRORS_ESCALATED` is a loop-breaker: the sudo child sets it and
    // preserves it across the exec, so if we somehow land here again with a
    // non-root euid we abort instead of spinning forever.
    snafu::ensure_whatever!(
        std::env::var("ARCH_MIRRORS_ESCALATED").is_err(),
        "The privileges has already been escalated, but the effective user is still \
        non-root. Breaking the cycle!"
    );
    tracing::info!("Escalating privileges with sudo");
    let current_exe =
        std::env::current_exe().whatever_context("Can't get current executable path")?;
    // Absolute path matches the care taken with `current_exe` — a
    // PATH-planted `sudo` must not intercept us.
    let status = Command::new("/usr/bin/sudo")
        .env("ARCH_MIRRORS_ESCALATED", "1")
        // Preserve `RUST_LOG` so the user's log-filter survives the
        // privilege jump; sudo's default env_reset would otherwise drop it.
        .arg("--preserve-env=RUST_LOG,ARCH_MIRRORS_ESCALATED")
        .arg(current_exe)
        .args(std::env::args().skip(1))
        .status()
        .whatever_context("Failed to execute sudo; install sudo or re-run as root")?;
    std::process::exit(status.code().unwrap_or(1));
}

/// Spawns this binary with `--worker`, collects its stdout, and decodes the
/// JSON-encoded list of winning mirror URLs.
fn spawn_worker_and_read_mirrors() -> Result<Vec<Url>, snafu::Whatever> {
    let current_exe =
        std::env::current_exe().whatever_context("Can't get current executable path")?;
    let child = Command::new(current_exe)
        .args(std::env::args().skip(1))
        .arg("--worker")
        .stdout(Stdio::piped())
        .spawn()
        .whatever_context("Can't spawn an unprivileged worker")?;
    let worker_output = child
        .wait_with_output()
        .whatever_context("Can't receive output from the worker")?;
    let stdout = String::from_utf8_lossy(&worker_output.stdout);

    if !worker_output.status.success() {
        if let Some(code) = worker_output.status.code() {
            snafu::whatever!("The worker has terminated with code {code}; stdout:\n{stdout}");
        } else {
            snafu::whatever!("The worker has terminated with error; stdout:\n{stdout}");
        }
    }

    serde_json::from_str::<Result<Vec<Url>, String>>(&stdout)
        .with_whatever_context(|_| format!("Unable to parse the stdout:\n{stdout:?}"))?
        .whatever_context("Discovering the best mirrors has failed")
}

/// Atomically replaces `/etc/pacman.d/mirrorlist` with pacman-compatible
/// `Server = ...` lines derived from the given URLs.
fn write_mirrorlist(mirrors: &[Url]) -> Result<(), snafu::Whatever> {
    let original = Utf8Path::new("/etc/pacman.d/mirrorlist");
    let meta = original
        .metadata()
        .whatever_context("Can't get the mirrorlist's meta")?;
    // Capture the existing file's permissions so the replacement lands with
    // the same mode — we never want to broaden access on `/etc`.
    let perm = meta.permissions();
    // Write into a NamedTempFile in the same directory as the target so the
    // final `persist()` is an atomic rename on the same filesystem.
    let mut output = tempfile::NamedTempFile::new_in("/etc/pacman.d/")
        .whatever_context("Can't create a temporary file")?;
    for url in mirrors {
        use std::io::Write;
        writeln!(
            output,
            "Server = {}",
            url.join("$repo/os/$arch").expect("Should be OK")
        )
        .whatever_context("Can't write a mirror")?;
    }
    output
        .as_file()
        .sync_all()
        .whatever_context("Can't sync temporary file")?;
    tracing::debug!("Temporary file populated");
    output
        .as_file()
        .set_permissions(perm)
        .whatever_context("Unable to update permissions of the temporary file")?;
    output
        .persist("/etc/pacman.d/mirrorlist")
        .whatever_context("Unable to persist the mirror list")?;
    tracing::info!("Mirrors list updated successfully");
    Ok(())
}

/// Permanently drops the process to the `nobody` user and group.
///
/// Used by the worker subprocess before doing any network I/O, so a
/// vulnerability in the parser or HTTP stack cannot be leveraged to write to
/// `/etc` or exfiltrate root-readable files.
fn drop_privileges() -> Result<(), snafu::Whatever> {
    let user = nix::unistd::User::from_name("nobody")
        .whatever_context("System error during 'nobody' user lookup")?
        .whatever_context("The 'nobody' user doesn't exist")?;

    // Rule of thumb: ALWAYS drop GID before UID.
    // Once you drop the user ID to a non-root user, the OS will
    // revoke your permission to change the group ID!
    nix::unistd::setgid(user.gid)
        .whatever_context("CRITICAL SECURITY FAILURE: Could not drop group privileges")?;
    nix::unistd::setuid(user.uid)
        .whatever_context("CRITICAL SECURITY FAILURE: Could not drop user privileges")?;
    Ok(())
}

// ---------- Discovery pipeline ----------

/// Synchronous wrapper that spins up a Tokio runtime and runs the async
/// discovery pipeline to completion.
fn discover_best_mirrors(
    dl_k: NonZeroUsize,
    ping_k: NonZeroUsize,
    countries: &[CountryCode],
) -> Result<Vec<Url>, snafu::Whatever> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .whatever_context("Can't initialize Tokio")?;
    rt.block_on(discover_best_mirrors_impl(dl_k, ping_k, countries))
}

/// Per-mirror bookkeeping threaded through the discovery pipeline.
///
/// Two independent typestate parameters track pipeline progress:
///
/// - `PING` — [`PingStatRunning`] during the latency phase,
///   [`PingStatComputed`] after statistics are bootstrapped.
/// - `DL` — `Option<f64>` while throughput is being measured (some mirrors
///   will fail to produce a number), bare `f64` after ranking has filtered
///   out the failures; the latter makes "has a measured speed" a
///   compile-time guarantee.
struct MirrorData<PING = PingStatRunning, DL = Option<f64>> {
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
    pub fn try_new(mirror: Mirror) -> Result<Self, snafu::Whatever> {
        let last_sync_url = mirror
            .url
            .join("lastsync")
            .whatever_context("Can't build the lastsync url")?;
        Ok(Self {
            mirror,
            last_sync_url,
            ping_stat: PingStatRunning::default(),
            dl_speed: None,
        })
    }

    /// Finalizes the ping statistics and transitions to the post-latency phase.
    pub fn compute_pings<R: ?Sized + Rng>(&self, rng: &mut R) -> MirrorData<PingStatComputed> {
        MirrorData {
            mirror: self.mirror.clone(),
            last_sync_url: self.last_sync_url.clone(),
            ping_stat: self.ping_stat.compute(rng),
            dl_speed: self.dl_speed,
        }
    }
}

impl MirrorData<PingStatComputed, Option<f64>> {
    /// Lifts the mirror into the "has a measured speed" typestate, or drops
    /// it entirely if the throughput phase produced no number.
    ///
    /// Shaped for use as an [`Iterator::filter_map`] predicate — the `None`
    /// return filters the mirror out, the `Some(_)` threads it forward with
    /// `dl_speed: f64`.
    pub fn into_measured(self) -> Option<MirrorData<PingStatComputed, f64>> {
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
async fn discover_best_mirrors_impl(
    dl_k: NonZeroUsize,
    ping_k: NonZeroUsize,
    countries: &[CountryCode],
) -> Result<Vec<Url>, snafu::Whatever> {
    let client = build_client();
    let mirrors = fetch_and_filter_mirrors(&client, countries).await?;
    let mirrors = latency_phase(&client, mirrors, Duration::from_secs(3)).await;
    let mirrors = compute_and_filter_pings(mirrors, ping_k)?;
    let mirrors = throughput_phase(&client, mirrors).await;
    let mirrors = rank_by_throughput(mirrors, dl_k)?;
    print_summary(&mirrors);
    Ok(mirrors.into_iter().map(|data| data.mirror.url).collect())
}

/// Single shared client for the whole pipeline: one connection pool, one UA,
/// one connect timeout. HTTP keep-alive across `core.db` → largest-package
/// downloads to the same mirror is a nice side effect.
fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(APP_USER_AGENT)
        .connect_timeout(Duration::from_secs(2))
        .build()
        .expect("Should be OK")
}

/// Phase 1: downloads the official mirrors list and filters it down to
/// HTTP(S) mirrors in any of `countries` whose last sync is within 48h.
async fn fetch_and_filter_mirrors(
    client: &reqwest::Client,
    countries: &[CountryCode],
) -> Result<Vec<MirrorData<PingStatRunning>>, snafu::Whatever> {
    let Mirrors::V3(mirrors) = client
        .get("https://archlinux.org/mirrors/status/json/")
        .send()
        .await
        .whatever_context("Can't fetch mirrors list")?
        .json()
        .await
        .whatever_context("Can't parse mirrors list")?;
    tracing::info!("Fetched {} mirrors", mirrors.urls.len());

    // 48h is a loose freshness gate: a mirror that's briefly behind during
    // its own sync cycle might still be the fastest, so we don't want the
    // cutoff too tight. Anything staler than that is almost certainly broken.
    let max_delay = Duration::from_hours(48);
    let oldest_sync = OffsetDateTime::now_utc() - max_delay;
    let kept = mirrors
        .urls
        .into_iter()
        .filter_map(|mirror| {
            if let Some(last_sync) = mirror.last_sync
                && let Some(delay) = mirror.delay
                && last_sync >= oldest_sync
                && delay <= max_delay.as_secs()
                && countries.contains(&mirror.country_code)
                // Rsync is pacman-compatible via separate tooling, but not
                // over plain HTTP — skip, since this binary writes
                // HTTP(S) `Server = ...` lines.
                && mirror.protocol != Protocol::Rsync
                && let Ok(mirror_data) = MirrorData::try_new(mirror)
            {
                Some(mirror_data)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    snafu::ensure_whatever!(!kept.is_empty(), "No mirrors available");
    tracing::info!(
        "Discovered {} mirrors for {}",
        kept.len(),
        format_countries(countries),
    );
    Ok(kept)
}

/// Renders a slice of country codes as a comma-separated list for log output.
fn format_countries(countries: &[CountryCode]) -> String {
    countries
        .iter()
        .map(CountryCode::as_code)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Phase 2a: probes every mirror's `lastsync` URL for `duration`, recording
/// per-probe latency (or errors) into each mirror's [`PingStatRunning`].
async fn latency_phase(
    client: &reqwest::Client,
    mut mirrors: Vec<MirrorData<PingStatRunning>>,
    duration: Duration,
) -> Vec<MirrorData<PingStatRunning>> {
    // Deadline shared by every ping stream and by each individual request
    // (see `ping_url` for the per-request timeout).
    let deadline = Instant::now() + duration;
    let streams = mirrors
        .iter()
        .enumerate()
        .map(|(n, mirror_data)| {
            arch_mirrors::ping_test::ping_url(
                client,
                mirror_data.last_sync_url.clone(),
                Duration::from_secs(1),
                deadline,
            )
            .map(move |result| (n, result))
        })
        .map(Box::pin)
        .collect::<Vec<_>>();
    let mut pings = futures_util::stream::select_all(streams);
    while let Some((n, result)) = pings.next().await {
        let mirror_data = &mut mirrors[n];
        match result {
            Ok(duration) => {
                mirror_data.ping_stat.record_ping(duration);
                tracing::debug!("{}: {duration:?}", mirror_data.mirror.url);
            }
            Err(err) => {
                mirror_data.ping_stat.record_error();
                tracing::debug!("{}: {err:?}", mirror_data.mirror.url);
            }
        }
    }
    mirrors
}

/// Phase 2b: turns raw ping samples into bootstrap statistics, drops anything
/// slower than 1s median, then keeps the `ping_k` fastest survivors.
fn compute_and_filter_pings(
    mirrors: Vec<MirrorData<PingStatRunning>>,
    ping_k: NonZeroUsize,
) -> Result<Vec<MirrorData<PingStatComputed>>, snafu::Whatever> {
    // Seeded with a constant so the bootstrap resampling produces the same
    // confidence intervals for the same inputs across runs — useful when
    // comparing two invocations made minutes apart.
    let mut rng = rand::rngs::StdRng::seed_from_u64(1337);
    let mut kept = mirrors
        .into_iter()
        .map(|data| data.compute_pings(&mut rng))
        // Anything slower than 1s median is not worth the download test.
        .filter(|data| data.ping_stat.median() <= Duration::from_secs(1))
        .collect::<Vec<_>>();
    snafu::ensure_whatever!(!kept.is_empty(), "No servers to continue with");
    kept.sort_by_key(|m| m.ping_stat.median());
    kept.truncate(ping_k.get());
    tracing::info!("Latency phase finished, kept {} mirrors", kept.len());
    if tracing::enabled!(tracing::Level::DEBUG) {
        for data in &kept {
            let low = data.ping_stat.low();
            let high = data.ping_stat.high();
            let median = data.ping_stat.median();
            tracing::debug!(
                { %data.mirror.url },
                "90% in {low:.2?}..{high:.2?}, median = {median:.2?}",
            );
        }
    }
    Ok(kept)
}

/// Phase 3a: measures throughput against each survivor, **serially**.
///
/// Running concurrent downloads would split local bandwidth between them
/// and distort the per-mirror measurement; that's why we don't parallelize.
async fn throughput_phase(
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
fn rank_by_throughput(
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
fn print_summary(mirrors: &[MirrorData<PingStatComputed, f64>]) {
    for data in mirrors {
        eprintln!(
            "{}:\n  * DL speed: {}\n  * TTFB: {:.2?}",
            data.mirror.url,
            data.dl_speed.human_throughput_bytes(),
            data.ping_stat.median()
        );
    }
}

/// Measures the download throughput of a single mirror.
///
/// First resolves the largest package via [`largest_file_discovery::discover`]
/// — which itself downloads and parses `core.db` — then downloads that
/// package for up to two seconds and returns the observed bytes-per-second.
async fn dl_mirror<T>(
    client: &reqwest::Client,
    mirror_data: &MirrorData<T>,
    dl_progress: &ProgressBar,
) -> Result<f64, snafu::Whatever> {
    const TIME_LIMIT: Duration = Duration::from_secs(2);

    let largest_file_url =
        arch_mirrors::largest_file_discovery::discover(client, &mirror_data.mirror.url, TIME_LIMIT)
            .await
            .whatever_context("Failed to discover the largest file")?;
    dl_progress.set_prefix(mirror_data.mirror.url.to_string());
    dl_progress.reset();
    let result = arch_mirrors::dl_test::download(
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
