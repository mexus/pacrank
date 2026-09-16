//! Discover the fastest Archlinux mirrors for a given country.
//!
//! This crate exposes the building blocks of the discovery pipeline:
//! fetching the official mirrors list from archlinux.org, measuring latency
//! by repeatedly issuing `HEAD` requests against each mirror's `lastsync`
//! file, and downloading the largest package from the `core` repository to
//! estimate throughput. The [`pipeline`] module composes them into the
//! ranked end-to-end run, and the binary entry point (`main.rs`) adds the
//! process plumbing around it — privilege escalation, the worker protocol,
//! and the `/etc/pacman.d/mirrorlist` rewrite.

use std::{sync::LazyLock, time::Duration};

/// Parser for pacman's per-package `desc` metadata.
pub mod arch_desc;
/// Auto-detect the user's nearest country (or top-K nearest countries) by
/// sample-pinging the global mirror list.
pub mod country_detect;
/// Timed HTTP download used to estimate mirror throughput.
pub mod dl_test;
/// Name resolution: backend selection plus the survey's resolve/ping hand-off.
pub mod dns;
/// Finds the largest package in a mirror's `core` repository.
pub mod largest_file_discovery;
/// Types mirroring the `mirrors/status/json/` endpoint plus country codes.
pub mod mirrors;
/// Summary statistics over ping samples.
pub mod ping_stat;
/// Repeated latency probing against an HTTP endpoint, plus a self-tuning
/// cap for cold probes.
pub mod ping_test;
/// The end-to-end discovery pipeline: fetch → filter → resolve → latency →
/// throughput → rank.
pub mod pipeline;

pub use mirrors::{CountryCode, Mirror, Mirrors};

/// HTTP `User-Agent` header sent by every outgoing request.
///
/// Leads with a `pacman/…` compatibility token — the same convention as
/// browsers' `Mozilla/5.0` prefix — because some mirrors sit behind WAF
/// rules that allowlist pacman's UA and answer everything else with an edge
/// 403 (`mirror.krfoss.org` does exactly that, verified 2026-09: bare
/// `pacrank/x` → 403, `pacman/7.0.0 pacrank/x` → 200). The claimed pacman
/// version is nominal, like the `5.0` in `Mozilla/5.0`.
///
/// The real identity follows the token: naming the tool is polite to mirror
/// operators and lets them filter or debug our probe traffic. That part is
/// derived at compile time from `Cargo.toml`.
pub static APP_USER_AGENT: &str = concat!(
    "pacman/7.0.0 ",
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
);

/// The bundled Mozilla root certificates, parsed once per process and handed
/// to [`reqwest::ClientBuilder::tls_certs_only`].
///
/// reqwest 0.13 verifies server certificates with `rustls-platform-verifier`
/// by default. On Android that verifier has to be initialized through the JVM,
/// which never happens under Termux (a bare Linux userland) — so the very
/// first HTTPS handshake panics with *"Expect rustls-platform-verifier to be
/// initialized"* (see issue #1). Pinning the client to this bundled root store
/// routes verification through webpki instead, sidestepping the platform
/// verifier entirely and making the binary self-contained on every target we
/// ship.
///
/// Parsing the DER blobs into `Certificate`s is pure CPU work over ~150
/// entries, and every client build in the process wants the exact same set —
/// so the result is cached in [`TLS_ROOTS`] instead of being rebuilt per call.
static TLS_ROOTS: LazyLock<Vec<reqwest::Certificate>> = LazyLock::new(|| {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .map(|der| reqwest::Certificate::from_der(der).expect("bundled webpki roots are valid DER"))
        .collect()
});

/// A clone of the cached root set — a fresh `Vec`, because `tls_certs_only`
/// consumes its argument by value.
pub fn tls_roots() -> Vec<reqwest::Certificate> {
    TLS_ROOTS.clone()
}

/// How long the shared client waits for a TCP (+ TLS) connection to be
/// established.
///
/// Connects are the cheap end of every request this crate makes, and both
/// the survey and the pipeline issue them in volume — a mirror that cannot
/// even complete a handshake within 2s has nothing worth measuring. Waits
/// *after* the connection (headers, body) are bounded per consumer
/// instead, where their budget belongs to the measurement being taken.
///
/// This is a *measurement* budget, and it belongs to mirrors alone. The one
/// request that is not a measurement — the mirror list itself, without which
/// there is no run at all — is far too important to give up on after 2s, and
/// reqwest has no per-request connect timeout to loosen it with, so
/// [`mirrors::fetch`] builds its own client through [`build_client_with`]
/// (see `mirrors::STATUS_CONNECT_TIMEOUT`).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// The shared HTTP client every network stage is built on: one UA, one
/// connect timeout, the bundled webpki roots, and the shared resolver's
/// cache.
///
/// Both the country survey and the discovery pipeline construct their
/// client here so the two stages make identical requests — same
/// `User-Agent` (see [`APP_USER_AGENT`] for why that exact string), same
/// `CONNECT_TIMEOUT`, same root store — and share the resolver cache
/// that keeps DNS time out of every measurement (the survey warms it
/// before pinging; the pipeline's resolve phase does the same).
pub fn build_client(
    resolver: crate::dns::SurveyResolver,
) -> Result<reqwest::Client, reqwest::Error> {
    build_client_with(resolver, CONNECT_TIMEOUT)
}

/// [`build_client`] with the connect budget spelled out by the caller.
///
/// Every client in the crate is born here, which is what keeps the
/// invariants the doc comment above lists from drifting apart: the connect
/// timeout is the only dial a caller gets, and [`mirrors::fetch`] is the
/// only caller that turns it — the mirror list is a prerequisite, not a
/// measurement, so it must not be held to a measurement's patience.
pub fn build_client_with(
    resolver: crate::dns::SurveyResolver,
    connect_timeout: Duration,
) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .user_agent(APP_USER_AGENT)
        .connect_timeout(connect_timeout)
        .tls_certs_only(tls_roots())
        .dns_resolver(resolver)
        .build()
}
