pub mod arch_desc;
pub mod dl_test;
pub mod largest_file_discovery;
pub mod mirrors;
pub mod ping_stat;
pub mod ping_test;

pub use mirrors::{CountryCode, Mirror, Mirrors, MirrorsV3, Protocol};

/// HTTP user agent.
pub static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);
