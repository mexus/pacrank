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
    /// Measure without the `nobody` sandbox: no sudo, no password prompt,
    /// and a hostile mirror's `core.db` parsed with your own privileges
    /// rather than nobody's. Only meaningful together with `--dry-run`.
    #[arg(long, requires = "dry_run")]
    no_sandbox: bool,

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

    /// Installs the mirror list handed over as JSON on stdin. The only
    /// branch that needs root; the parent spawns it under sudo.
    #[arg(long, hide(true))]
    apply: bool,

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
        no_sandbox,
        worker,
        apply,
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

    // The privileged tail of a run, spawned by `install_via_sudo` below. It
    // needs nothing but the JSON on its stdin, so it returns here — before
    // country resolution could drag a network survey into the root branch.
    if apply {
        return run_apply();
    }

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

    // The remaining modes of operation (`--apply` returned above):
    //   - --worker:  drop to `nobody`, measure, emit JSON on stdout. Tested
    //                first because a dry run forwards its own argv to the
    //                worker it spawns, `--dry-run` and all.
    //   - dry-run:   spawn that same worker — the measurements reach the
    //                same hostile bytes either way — and simply never spawn
    //                the `--apply` half.
    //   - default:   spawn the worker, read its JSON stdout, then hand the
    //                winners to an `--apply` child that writes
    //                `/etc/pacman.d/mirrorlist`.
    // The split keeps network I/O unprivileged while isolating the file
    // rewrite in a minimal privileged branch — one that, started from an
    // unprivileged parent, only comes into existence once the measurements
    // are over.
    if worker {
        run_worker(dl_k, ping_k, &country)
    } else {
        // Only a list we resolved ourselves needs injecting into the child's
        // argv; an explicit `-c` is already part of `env::args()`.
        let injected: &[CountryCode] = if auto_detected { &country } else { &[] };
        let child_args = forwarded_args(injected);
        if dry_run {
            run_dry_run(dl_k, ping_k, &country, &child_args, !no_sandbox)
        } else {
            run_update(&child_args)
        }
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

/// Builds the argv to forward to the `--worker` subprocess — our own
/// arguments minus `argv[0]`, with each country in `injected` appended as
/// `-c <CODE>`.
///
/// Injecting the countries here means the worker sees a fully specified
/// `--country` list and never re-runs auto-detection itself. Only the ones
/// *this* process auto-detected belong in `injected`: an explicit `-c` is
/// already part of `env::args()`, and appending it again would hand the
/// worker a doubled list.
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
/// Writing nothing makes this the harmless-looking mode, but it measures
/// exactly what an update measures: the same `core.db` from the same
/// unvetted mirror, through the same magic-byte-sniffed decompressor. So it
/// earns the same sandbox — the worker is spawned under sudo just as an
/// update spawns it, and the `--apply` half simply never happens.
///
/// `--no-sandbox` buys back the password prompt by measuring here instead,
/// as the invoking user. Root needs neither: it can reach `setuid(nobody)`
/// without a child, and `sudo pacrank --dry-run` has already paid for its
/// privileges anyway.
fn run_dry_run(
    dl_k: NonZeroUsize,
    ping_k: NonZeroUsize,
    countries: &[CountryCode],
    child_args: &[String],
    sandbox: bool,
) -> Result<(), snafu::Whatever> {
    if nix::unistd::Uid::effective().is_root() {
        drop_privileges()?;
        pipeline::discover_best_mirrors(dl_k, ping_k, countries)?;
    } else if sandbox {
        // The winners are already on our stderr: the worker prints the
        // per-mirror summary itself, and only the JSON goes down the pipe.
        spawn_worker_and_read_mirrors(child_args, true)?;
    } else {
        tracing::warn!(
            "--no-sandbox: measuring as you, not as 'nobody'. A hostile mirror's core.db \
             is parsed with your privileges."
        );
        pipeline::discover_best_mirrors(dl_k, ping_k, countries)?;
    }
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

/// Privileged entry point: installs the mirror list handed to us on stdin.
///
/// The only branch that runs as root, and it lives for one `rename(2)`: it
/// opens no socket, detects no country and trusts nothing but the JSON its
/// parent wrote into the pipe.
fn run_apply() -> Result<(), snafu::Whatever> {
    snafu::ensure_whatever!(
        nix::unistd::Uid::effective().is_root(),
        "--apply needs root; the parent spawns it under sudo."
    );
    let mirrors: Vec<Url> = serde_json::from_reader(std::io::stdin().lock())
        .whatever_context("Can't parse the mirrors handed over on stdin")?;
    // An empty list would leave pacman with no servers at all. The pipeline
    // never produces one, so this guards against a broken hand-over rather
    // than an expected outcome.
    snafu::ensure_whatever!(
        !mirrors.is_empty(),
        "Refusing to install an empty mirror list"
    );
    write_mirrorlist(&mirrors)
}

/// Default entry point: measure in a sandboxed worker, then install the
/// winners.
///
/// Root is never held across the measurement. Invoked as a regular user,
/// each half gets a sudo child of its own: one that lives just long enough
/// to reach `setuid(nobody)`, one that lives just long enough to rename a
/// file. The minutes of network I/O in between have no privileged process
/// attached to them at all.
///
/// The price is a second `sudo`, which prompts again when the run outlives
/// the sudo timestamp — hence the two escalations logging what they are for
/// rather than a bare "escalating".
fn run_update(child_args: &[String]) -> Result<(), snafu::Whatever> {
    // Already root (`sudo pacrank`): the worker is ours to spawn directly,
    // and installing needs no second process at all. Nothing can shorten
    // root's lifetime on this path — the user handed it to us for the whole
    // run.
    let escalate = !nix::unistd::Uid::effective().is_root();
    let mirrors = spawn_worker_and_read_mirrors(child_args, escalate)?;
    if escalate {
        install_via_sudo(&mirrors)
    } else {
        write_mirrorlist(&mirrors)
    }
}

// ---------- Child process helpers ----------

/// Builds a [`Command`] that re-runs this binary, behind `/usr/bin/sudo`
/// when `escalate` is set.
///
/// Both paths are absolute on purpose: `current_exe` resolves ours, and a
/// PATH-planted `sudo` lookalike must not intercept the other.
fn self_command(escalate: bool) -> Result<Command, snafu::Whatever> {
    let current_exe =
        std::env::current_exe().whatever_context("Can't get current executable path")?;
    if !escalate {
        return Ok(Command::new(current_exe));
    }
    let mut command = Command::new("/usr/bin/sudo");
    // Preserve `RUST_LOG` so the user's log-filter survives the privilege
    // jump; sudo's default env_reset would otherwise drop it.
    command.arg("--preserve-env=RUST_LOG").arg(current_exe);
    Ok(command)
}

/// Hands the winning mirrors to a short-lived root child over a pipe.
///
/// argv would carry a handful of public URLs just as well, but stdin reuses
/// the JSON codec the worker already speaks — same types, direction flipped
/// — and taking it costs the child nothing: sudo reads the password from
/// the terminal, not from the stdin we occupy here.
fn install_via_sudo(mirrors: &[Url]) -> Result<(), snafu::Whatever> {
    tracing::info!("Escalating privileges with sudo to update the mirror list");
    // `--apply` is the entire argv: the mirrors arrive on stdin, and
    // forwarding the rest of ours would only hand the root branch flags it
    // must not act on.
    let mut child = self_command(true)?
        .arg("--apply")
        .stdin(Stdio::piped())
        .spawn()
        .whatever_context("Failed to execute sudo; install sudo or re-run as root")?;
    let mut stdin = child.stdin.take().expect("Stdin is piped");
    let handover = serde_json::to_writer(&mut stdin, mirrors);
    // The child reads to EOF before it touches `/etc`, so the pipe has to be
    // closed before we start waiting on its exit code.
    drop(stdin);
    let status = child
        .wait()
        .whatever_context("Can't wait for the privileged child")?;
    // Reported before the hand-over: a refused authentication reaps sudo
    // before the child can drain the pipe, and "the escalation failed" is
    // the honest diagnosis of the broken pipe that follows from it.
    snafu::ensure_whatever!(
        status.success(),
        "Updating the mirror list failed ({status})"
    );
    handover.whatever_context("Can't hand the mirrors over to the privileged child")?;
    Ok(())
}

/// Spawns this binary with `--worker`, collects its stdout, and decodes the
/// JSON-encoded list of winning mirror URLs.
///
/// The worker needs root only in order to give it up: `setuid` to `nobody`
/// is itself a privileged operation, so an unprivileged parent has to
/// escalate to build the sandbox it wants — and that child reaches the
/// syscall within milliseconds of exec.
fn spawn_worker_and_read_mirrors(
    child_args: &[String],
    escalate: bool,
) -> Result<Vec<Url>, snafu::Whatever> {
    if escalate {
        tracing::info!("Escalating privileges with sudo to sandbox the worker as 'nobody'");
    }
    let child = self_command(escalate)?
        .args(child_args)
        .arg("--worker")
        .stdout(Stdio::piped())
        .spawn()
        .whatever_context(if escalate {
            "Can't spawn the worker under sudo; install sudo or re-run as root"
        } else {
            "Can't spawn an unprivileged worker"
        })?;
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

// `concat!` only accepts literals, so both consts below build from this
// macro instead — one spelling of the directory rather than two that
// could drift apart.
macro_rules! pacman_d {
    () => {
        "/etc/pacman.d/"
    };
}

/// The pacman configuration directory the mirrorlist lives in.
const PACMAN_D_DIR: &str = pacman_d!();

/// The mirrorlist file this tool atomically replaces.
const MIRRORLIST_PATH: &str = concat!(pacman_d!(), "mirrorlist");

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

    // Rule of thumb: ALWAYS drop the supplementary groups first, then the
    // GID, then the UID. Once you drop the user ID to a non-root user, the
    // OS will revoke your permission to change either of the other two!
    //
    // `setgroups` is the step that is easy to miss, because neither
    // `setgid` nor `setuid` touches the supplementary group vector: without
    // it the worker keeps whatever vector it inherited, and under sudo that
    // vector is root's. A `nobody` worker carrying group 0 into every file
    // access it makes is not the sandbox this function advertises.
    nix::unistd::setgroups(&[user.gid])
        .whatever_context("CRITICAL SECURITY FAILURE: Could not drop supplementary groups")?;
    nix::unistd::setgid(user.gid)
        .whatever_context("CRITICAL SECURITY FAILURE: Could not drop group privileges")?;
    nix::unistd::setuid(user.uid)
        .whatever_context("CRITICAL SECURITY FAILURE: Could not drop user privileges")?;
    Ok(())
}

#[cfg(test)]
mod test {
    use clap::Parser as _;

    use super::{Args, validate_detect_threshold};

    /// `--no-sandbox` only describes what a dry run does; on an update the
    /// worker is spawned by a parent that has to escalate for `--apply`
    /// regardless, so skipping the sandbox would cost a password and buy
    /// nothing. Silently ignoring it there would be the worse answer.
    #[test]
    fn no_sandbox_is_refused_outside_a_dry_run() {
        Args::try_parse_from(["pacrank", "--no-sandbox"])
            .expect_err("--no-sandbox must require --dry-run");
        Args::try_parse_from(["pacrank", "--no-sandbox", "--dry-run"])
            .expect("--no-sandbox belongs with --dry-run");
    }

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
