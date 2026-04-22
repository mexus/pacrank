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
/// Timed HTTP download used to estimate mirror throughput.
pub mod dl_test;
/// Finds the largest package in a mirror's `core` repository.
pub mod largest_file_discovery;
/// Types mirroring the `mirrors/status/json/` endpoint plus country codes.
pub mod mirrors;
/// Summary statistics (bootstrap confidence intervals) over ping samples.
pub mod ping_stat;
/// Repeated latency probing against an HTTP endpoint.
pub mod ping_test;

pub use mirrors::{CountryCode, Mirror, Mirrors, MirrorsV3, Protocol};

/// HTTP `User-Agent` header sent by every outgoing request.
///
/// Identifying the tool is polite to mirror operators and helps with debugging
/// on their side. The value is derived at compile time from `Cargo.toml`.
pub static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);
