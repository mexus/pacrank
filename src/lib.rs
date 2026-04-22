pub mod arch_desc;
pub mod dl_test;
pub mod largest_file_discovery;
pub mod mirrors;
pub mod ping_stat;
pub mod ping_test;

pub use mirrors::{CountryCode, Mirror, Mirrors, MirrorsV3, Protocol};
