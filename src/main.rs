use std::{
    num::NonZeroUsize,
    os::unix::fs::{MetadataExt, fchown},
    process::{Command, Stdio},
};

use camino::Utf8Path;
use clap::{CommandFactory, Parser};
use display_error_chain::DisplayErrorChain;
use nonzero_ext::nonzero;
use pacrank::{
    CountryCode,
    country_detect::{self, DetectOptions},
    pipeline,
};
use snafu::{OptionExt, ResultExt};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;

/// Discover the fastest available Archlinux mirrors for the current location.
#[derive(Debug, Parser)]
#[command(version)]
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
    /// more than one (e.g. `-c US -c DE`). When omitted, the closest
    /// countries are auto-detected by sample-pinging the global mirror list.
    #[arg(long, short, value_enum, ignore_case = true)]
    country: Vec<CountryCode>,

    /// Number of fastest-pinged mirrors whose median latency forms the
    /// per-mirror baseline used for country auto-detection.
    #[arg(long, default_value_t = nonzero!(5usize))]
    detect_baseline_n: NonZeroUsize,
    /// Mirrors whose latency exceeds `threshold * baseline` are dropped
    /// before country auto-detection picks winners.
    #[arg(long, default_value_t = 1.5)]
    detect_threshold: f64,
    /// Maximum number of distinct countries returned by auto-detection.
    #[arg(long, default_value_t = nonzero!(3usize))]
    detect_k_countries: NonZeroUsize,
    /// Bypass the country cache for this invocation (always re-detect).
    #[arg(long)]
    no_country_cache: bool,

    /// Runs a worker that drops privileges, discovers the fastest mirrors and
    /// reports them back.
    #[arg(long, hide(true))]
    worker: bool,

    /// Emit a shell completion script to stdout and exit.
    #[arg(long, value_name = "SHELL", value_enum, hide = true, exclusive = true)]
    generate_completions: Option<clap_complete::Shell>,
}

#[snafu::report]
fn main() -> Result<(), snafu::Whatever> {
    let Args {
        ping_k,
        dl_k,
        dry_run,
        worker,
        mut country,
        detect_baseline_n,
        detect_threshold,
        detect_k_countries,
        no_country_cache,
        generate_completions,
    } = Args::parse();

    if let Some(shell) = generate_completions {
        clap_complete::generate(
            shell,
            &mut Args::command(),
            "pacrank",
            &mut std::io::stdout(),
        );
        return Ok(());
    }

    // A non-positive threshold is a degenerate one: every latency exceeds
    // `0 × baseline`, so auto-detection would drop every mirror and fail
    // with a much less actionable error than this one. (`NaN` fails the
    // same comparison and is rejected here too.)
    validate_detect_threshold(detect_threshold)?;

    init_tracing();

    // Country auto-detection runs in the user-context parent only — never
    // in the worker, which receives the resolved list via argv. Doing it
    // here guarantees the cache lands under the invoking user's HOME, not
    // root's, and that we don't survey twice (parent + worker).
    let auto_detected = country.is_empty() && !worker;
    if auto_detected {
        country = country_detect::resolve(DetectOptions {
            baseline_n: detect_baseline_n,
            threshold: detect_threshold,
            k_countries: detect_k_countries,
            read_cache: !no_country_cache,
            // --dry-run must leave no side effects, so skip persisting the
            // detection result even when caching is otherwise enabled.
            write_cache: !no_country_cache && !dry_run,
        })
        .whatever_context("Country auto-detection failed")?;
    }
    // `-c` accepts the same code twice, so normalize before anything
    // downstream filters or logs the list.
    CountryCode::dedup(&mut country);
    snafu::ensure_whatever!(
        !country.is_empty(),
        "No countries available — pass --country/-c explicitly."
    );

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
        // Only a list we resolved ourselves needs injecting into the child's
        // argv; an explicit `-c` is already part of `env::args()`.
        let injected: &[CountryCode] = if auto_detected { &country } else { &[] };
        run_privileged(&forwarded_args(injected))
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

/// Rejects a degenerate `--detect-threshold` right after argument parsing.
///
/// The zero/NaN cutoff makes selection drop every mirror (or never fire),
/// and the library would only report that much later as a far-from-the-
/// cause "no mirrors survived" after a full survey. The library's own
/// `DetectError::InvalidThreshold` guards the same invariant for direct
/// callers; this front door adds the flag's name to the message.
fn validate_detect_threshold(threshold: f64) -> Result<(), snafu::Whatever> {
    snafu::ensure_whatever!(
        threshold > 0.0,
        "--detect-threshold must be positive, got {threshold}"
    );
    Ok(())
}

/// Builds the argv to forward to a child process (sudo re-exec or
/// `--worker` subprocess) — our own arguments minus `argv[0]`, with each
/// country in `injected` appended as `-c <CODE>`.
///
/// Injecting the countries here means the child sees a fully specified
/// `--country` list and never re-runs auto-detection itself. Only the ones
/// *this* process auto-detected belong in `injected`: an explicit `-c` is
/// already part of `env::args()`, and appending it again would hand the child
/// a doubled list, one extra copy per hop (parent → sudo child → worker).
fn forwarded_args(injected: &[CountryCode]) -> Vec<String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    for cc in injected {
        args.push("-c".to_string());
        args.push(cc.as_code().to_string());
    }
    args
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
    pipeline::discover_best_mirrors(dl_k, ping_k, countries)?;
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
    // The parent is responsible for resolving `--country` (either from the
    // user or via auto-detection) before spawning us. If we somehow land
    // here with no countries it would silently produce an empty mirror
    // list — fail loudly instead.
    snafu::ensure_whatever!(
        !countries.is_empty(),
        "Worker invoked without --country; the privileged parent must resolve countries first."
    );
    drop_privileges()?;
    let result = pipeline::discover_best_mirrors(dl_k, ping_k, countries)
        .map_err(|e| DisplayErrorChain::new(e).to_string());
    serde_json::to_writer(std::io::stdout(), &result)
        .whatever_context("Failed to serialize the result")?;
    Ok(())
}

/// Privileged parent entry point: make sure we're root, spawn an unprivileged
/// worker, and atomically replace `/etc/pacman.d/mirrorlist` with the result.
fn run_privileged(child_args: &[String]) -> Result<(), snafu::Whatever> {
    escalate_if_needed(child_args)?;
    let mirrors = spawn_worker_and_read_mirrors(child_args)?;
    write_mirrorlist(&mirrors)?;
    Ok(())
}

// ---------- Privileged parent helpers ----------

/// Re-execs the process under sudo when the effective UID isn't root.
///
/// If escalation happens, this function does not return — it exits the
/// current process with the sudo child's exit code. On the already-root path
/// it simply returns `Ok(())`.
fn escalate_if_needed(child_args: &[String]) -> Result<(), snafu::Whatever> {
    if nix::unistd::Uid::effective().is_root() {
        return Ok(());
    }
    // `PACRANK_ESCALATED` is a loop-breaker: the sudo child sets it and
    // preserves it across the exec, so if we somehow land here again with a
    // non-root euid we abort instead of spinning forever.
    snafu::ensure_whatever!(
        std::env::var("PACRANK_ESCALATED").is_err(),
        "The privileges has already been escalated, but the effective user is still \
        non-root. Breaking the cycle!"
    );
    tracing::info!("Escalating privileges with sudo");
    let current_exe =
        std::env::current_exe().whatever_context("Can't get current executable path")?;
    // Absolute path matches the care taken with `current_exe` — a
    // PATH-planted `sudo` must not intercept us.
    let status = Command::new("/usr/bin/sudo")
        .env("PACRANK_ESCALATED", "1")
        // Preserve `RUST_LOG` so the user's log-filter survives the
        // privilege jump; sudo's default env_reset would otherwise drop it.
        .arg("--preserve-env=RUST_LOG,PACRANK_ESCALATED")
        .arg(current_exe)
        .args(child_args)
        .status()
        .whatever_context("Failed to execute sudo; install sudo or re-run as root")?;
    std::process::exit(status.code().unwrap_or(1));
}

/// Spawns this binary with `--worker`, collects its stdout, and decodes the
/// JSON-encoded list of winning mirror URLs.
fn spawn_worker_and_read_mirrors(child_args: &[String]) -> Result<Vec<Url>, snafu::Whatever> {
    let current_exe =
        std::env::current_exe().whatever_context("Can't get current executable path")?;
    let child = Command::new(current_exe)
        .args(child_args)
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

/// The pacman configuration directory the mirrorlist lives in.
const PACMAN_D_DIR: &str = "/etc/pacman.d/";

/// The mirrorlist file this tool atomically replaces.
const MIRRORLIST_PATH: &str = "/etc/pacman.d/mirrorlist";

/// Atomically replaces `/etc/pacman.d/mirrorlist` with pacman-compatible
/// `Server = ...` lines derived from the given URLs.
fn write_mirrorlist(mirrors: &[Url]) -> Result<(), snafu::Whatever> {
    let original = Utf8Path::new(MIRRORLIST_PATH);
    let meta = original
        .metadata()
        .whatever_context("Can't get the mirrorlist's meta")?;
    // Capture the existing file's permissions so the replacement lands with
    // the same mode — we never want to broaden access on `/etc`.
    let perm = meta.permissions();
    let uid = meta.uid();
    let gid = meta.gid();
    // Write into a NamedTempFile in the same directory as the target so the
    // final `persist()` is an atomic rename on the same filesystem.
    let mut output = tempfile::NamedTempFile::new_in(PACMAN_D_DIR)
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
    fchown(output.as_file(), Some(uid), Some(gid))
        .whatever_context("Unable to update ownership of the temporary file")?;
    output
        .persist(MIRRORLIST_PATH)
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

#[cfg(test)]
mod test {
    use super::validate_detect_threshold;

    #[test]
    fn positive_thresholds_pass() {
        for threshold in [1.5, f64::MIN_POSITIVE, 42.0, f64::INFINITY] {
            assert!(
                validate_detect_threshold(threshold).is_ok(),
                "{threshold} is a usable multiplier"
            );
        }
    }

    #[test]
    fn degenerate_thresholds_are_rejected() {
        // NaN fails the comparison like every other non-positive value;
        // -0.0 is not greater than zero either.
        for threshold in [0.0, -0.0, -1.5, f64::NAN, f64::NEG_INFINITY] {
            let err = validate_detect_threshold(threshold).expect_err("must be rejected");
            assert!(
                err.to_string().contains("--detect-threshold"),
                "the message should name the flag: {err}"
            );
        }
    }
}
