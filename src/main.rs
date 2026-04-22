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

    /// Limit mirrors to this country.
    #[arg(long, short, default_value_t = CountryCode::RU)]
    country: CountryCode,

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
    } = Args::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    if dry_run {
        drop_privileges()?;
        discover_best_mirrors(dl_k, ping_k, country)?;
        tracing::info!("Refusing to update the mirror list (dry run enabled)");
    } else if worker {
        // Worker process.
        drop_privileges()?;
        let result = discover_best_mirrors(dl_k, ping_k, country)
            .map_err(|e| DisplayErrorChain::new(e).to_string());
        serde_json::to_writer(std::io::stdout(), &result)
            .whatever_context("Failed to serialize the result")?;
    } else {
        // Main process.
        let current_exe =
            std::env::current_exe().whatever_context("Can't get current executable path")?;

        if !nix::unistd::Uid::effective().is_root() {
            // Need escalation!
            snafu::ensure_whatever!(
                std::env::var("ARCH_MIRRORS_ESCALATED").is_err(),
                "The privileges has already been escalated, but the effective user is still \
                non-root. Breaking the cycle!"
            );
            tracing::info!("Escalating privileges with sudo");
            let status = Command::new("/usr/bin/sudo")
                .env("ARCH_MIRRORS_ESCALATED", "1")
                .arg("--preserve-env=RUST_LOG,ARCH_MIRRORS_ESCALATED")
                .arg(current_exe)
                .args(std::env::args().skip(1))
                .status()
                .whatever_context("Failed to execute sudo; install sudo or re-run as root")?;
            std::process::exit(status.code().unwrap_or(1));
        }

        let original = Utf8Path::new("/etc/pacman.d/mirrorlist");
        let meta = original
            .metadata()
            .whatever_context("Can't get the mirrorlist's meta")?;
        let perm = meta.permissions();
        let mut output = tempfile::NamedTempFile::new_in("/etc/pacman.d/")
            .whatever_context("Can't create a temporary file")?;

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
                snafu::whatever!("The worker has terminated with code {code}; stdout:\n{stdout}")
            } else {
                snafu::whatever!("The worker has terminated with error; stdout:\n{stdout}");
            }
        } else {
            let mirrors = serde_json::from_str::<Result<Vec<Url>, String>>(&stdout)
                .with_whatever_context(|_| format!("Unable to parse the stdout:\n{stdout:?}"))?
                .whatever_context("Discovering the best mirrors has failed")?;
            for url in &mirrors {
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
        }
    }

    Ok(())
}

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

fn discover_best_mirrors(
    dl_k: NonZeroUsize,
    ping_k: NonZeroUsize,
    country: CountryCode,
) -> Result<Vec<Url>, snafu::Whatever> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .whatever_context("Can't initialize Tokio")?;
    rt.block_on(discover_best_mirrors_impl(dl_k, ping_k, country))
}

struct MirrorData<PING = PingStatRunning> {
    mirror: Mirror,
    last_sync_url: Url,
    ping_stat: PING,
    dl_speed: f64,
}

impl MirrorData<PingStatRunning> {
    pub fn try_new(mirror: Mirror) -> Result<Self, snafu::Whatever> {
        let last_sync_url = mirror
            .url
            .join("lastsync")
            .whatever_context("Can't build the lastsync url")?;
        Ok(Self {
            mirror,
            last_sync_url,
            ping_stat: PingStatRunning::default(),
            dl_speed: f64::NEG_INFINITY,
        })
    }

    pub fn compute_pings<R: ?Sized + Rng>(&self, rng: &mut R) -> MirrorData<PingStatComputed> {
        MirrorData {
            mirror: self.mirror.clone(),
            last_sync_url: self.last_sync_url.clone(),
            ping_stat: self.ping_stat.compute(rng),
            dl_speed: self.dl_speed,
        }
    }
}

async fn discover_best_mirrors_impl(
    dl_k: std::num::NonZero<usize>,
    ping_k: std::num::NonZero<usize>,
    country: CountryCode,
) -> Result<Vec<Url>, snafu::Whatever> {
    let client = reqwest::Client::builder()
        .user_agent(APP_USER_AGENT)
        .connect_timeout(Duration::from_secs(2))
        .build()
        .expect("Should be OK");
    let Mirrors::V3(mirrors) = client
        .get("https://archlinux.org/mirrors/status/json/")
        .send()
        .await
        .whatever_context("Can't fetch mirrors list")?
        .json()
        .await
        .whatever_context("Can't parse mirrors list")?;
    tracing::info!("Fetched {} mirrors", mirrors.urls.len());
    let max_delay = Duration::from_hours(48);
    let oldest_sync = OffsetDateTime::now_utc() - max_delay;
    let mut ru_list = mirrors
        .urls
        .into_iter()
        .filter_map(|mirror| {
            if let Some(last_sync) = mirror.last_sync
                && let Some(delay) = mirror.delay
                && last_sync >= oldest_sync
                && delay <= max_delay.as_secs()
                && mirror.country_code == country
                && mirror.protocol != Protocol::Rsync
                && let Ok(mirror_data) = MirrorData::try_new(mirror)
            {
                Some(mirror_data)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    snafu::ensure_whatever!(!ru_list.is_empty(), "No mirrors available");
    tracing::info!("Discovered {} mirrors for {country}", ru_list.len());
    let last_ping = Instant::now() + Duration::from_secs(3);
    let streams = ru_list
        .iter()
        .enumerate()
        .map(|(n, mirror_data)| {
            arch_mirrors::ping_test::ping_url(
                &client,
                mirror_data.last_sync_url.clone(),
                Duration::from_secs(1),
                last_ping,
            )
            .map(move |result| (n, result))
        })
        .map(Box::pin)
        .collect::<Vec<_>>();
    let mut pings = futures_util::stream::select_all(streams);
    while let Some((n, result)) = pings.next().await {
        let mirror_data = &mut ru_list[n];
        match result {
            Ok(duration) => {
                mirror_data.ping_stat.record_ping(duration);
                tracing::debug!("{}: {duration:?}", mirror_data.mirror.url);
            }
            Err(err) => {
                mirror_data.ping_stat.record_error();
                tracing::warn!("{}: {err:?}", mirror_data.mirror.url);
            }
        }
    }
    tracing::info!("Latency phase finished");
    let mut rng = rand::rngs::StdRng::seed_from_u64(1337);
    let mut ru_list = ru_list
        .into_iter()
        .map(|data| data.compute_pings(&mut rng))
        .filter(|data| data.ping_stat.median() <= Duration::from_secs(1))
        .collect::<Vec<_>>();
    snafu::ensure_whatever!(!ru_list.is_empty(), "No servers to continue with");
    ru_list.sort_by_key(|m| m.ping_stat.median());
    ru_list.truncate(ping_k.get());
    if tracing::enabled!(tracing::Level::DEBUG) {
        for data in &ru_list {
            let low = data.ping_stat.low();
            let high = data.ping_stat.high();
            let median = data.ping_stat.median();
            tracing::debug!(
                { %data.mirror.url },
                "90% in {low:.2?}..{high:.2?}, median = {median:.2?}",
            );
        }
    }
    let all_progress = MultiProgress::new();
    let mirrors_progress = all_progress.add(
        ProgressBar::new(ru_list.len() as u64).with_style(
            ProgressStyle::with_template(
                "Processing {pos:.cyan}/{len:.green} mirror {bar:20.cyan/blue} (elapsed {elapsed}, eta {eta})",
            )
            .expect("Template must be OK"),
        ),
    );
    let dl_progress = ProgressBar::new_spinner().with_style(
        ProgressStyle::with_template(
            "{prefix:.cyan}: {elapsed} ({bytes}/{total_bytes}): {bytes_per_sec:.green}",
        )
        .expect("Must be OK"),
    );
    let pb = all_progress.add(dl_progress);
    for data in &mut ru_list {
        mirrors_progress.inc(1);
        match dl_mirror(&client, data, &pb).await {
            Ok(speed) => {
                data.dl_speed = speed;
            }
            Err(e) => {
                tracing::warn!("{}: {}", data.mirror.url, DisplayErrorChain::new(&e))
            }
        }
    }
    mirrors_progress.finish_and_clear();
    pb.finish_and_clear();
    drop(all_progress);
    tracing::info!("DL speed phase finished");
    ru_list.retain(|data| data.dl_speed.is_finite());
    snafu::ensure_whatever!(!ru_list.is_empty(), "No servers to continue with");
    ru_list.sort_by(|a, b| a.dl_speed.total_cmp(&b.dl_speed).reverse());
    ru_list.truncate(dl_k.get());
    for data in &ru_list {
        eprintln!(
            "{}:\n  * DL speed: {}\n  * TTFB: {:.2?}",
            data.mirror.url,
            data.dl_speed.human_throughput_bytes(),
            data.ping_stat.median()
        );
    }
    Ok(ru_list.into_iter().map(|data| data.mirror.url).collect())
}

async fn dl_mirror<T>(
    client: &reqwest::Client,
    mirror_data: &MirrorData<T>,
    dl_progress: &ProgressBar,
) -> Result<f64, snafu::Whatever> {
    let largest_file_url =
        arch_mirrors::largest_file_discovery::discover(client, &mirror_data.mirror.url)
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
        Duration::from_secs(2),
    )
    .await;
    dl_progress.finish();
    let (bytes, time) = result.whatever_context("Failed to download the largest file")?;
    let speed = bytes as f64 / time.as_secs_f64();
    tracing::debug!(
        "{}: {bytes} bytes in {time:.2?}, speed = {:.2} KB/s",
        largest_file_url,
        speed / 1024.
    );
    Ok(speed)
}
