//! Discover the fastest Archlinux mirrors for a given country.
//!
//! This crate exposes the building blocks of the discovery pipeline:
//! fetching the official mirrors list from archlinux.org, measuring latency
//! by repeatedly issuing `HEAD` requests against each mirror's `lastsync`
//! file, and downloading the largest package from the `core` repository to
//! estimate throughput. The binary entry point (`main.rs`) wires these
//! pieces together and rewrites `/etc/pacman.d/mirrorlist` with the results.

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
/// Summary statistics (bootstrap confidence intervals) over ping samples.
pub mod ping_stat;
/// Repeated latency probing against an HTTP endpoint, plus a self-tuning
/// cap for cold probes.
pub mod ping_test;

pub use mirrors::{CountryCode, Mirror, Mirrors, MirrorsV3, Protocol};

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

/// The bundled Mozilla root certificates, ready to hand to
/// [`reqwest::ClientBuilder::tls_certs_only`].
///
/// reqwest 0.13 verifies server certificates with `rustls-platform-verifier`
/// by default. On Android that verifier has to be initialized through the JVM,
/// which never happens under Termux (a bare Linux userland) — so the very
/// first HTTPS handshake panics with *"Expect rustls-platform-verifier to be
/// initialized"* (see issue #1). Pinning the client to this bundled root store
/// routes verification through webpki instead, sidestepping the platform
/// verifier entirely and making the binary self-contained on every target we
/// ship.
pub fn tls_roots() -> Vec<reqwest::Certificate> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .map(|der| reqwest::Certificate::from_der(der).expect("bundled webpki roots are valid DER"))
        .collect()
}
