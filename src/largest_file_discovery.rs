//! Discover the largest package file served by an Archlinux mirror.
//!
//! Picking the largest package gives the throughput test a long-lived chunk
//! to measure against — small packages are dominated by connection setup
//! noise. We fetch the `core` repository database (a compressed tar of
//! per-package `desc` files) at `CORE_REPO_DIR`, walk the archive, and
//! return the URL of the package with the largest `%CSIZE%`.

use std::{io::Read, time::Duration};

use camino::Utf8Path;
use display_error_chain::DisplayErrorChain;
use snafu::{OptionExt, ResultExt, Snafu};
use url::Url;

/// Path of the `core` repository directory on a mirror, relative to the
/// mirror's base URL.
const CORE_REPO_DIR: &str = "core/os/x86_64/";

/// Errors reported by [`discover`].
#[derive(Debug, Snafu)]
pub enum DiscoveryError {
    /// The `core.db` URL couldn't be constructed from the mirror's base URL.
    InvalidCoreUrl { source: url::ParseError },
    /// The request for `core.db` failed before any response was received.
    RequestFailed {
        /// URL that was requested.
        url: Url,
        source: reqwest::Error,
    },
    /// The response for `core.db` was received but reading the body failed.
    DownloadFailed {
        /// URL whose body couldn't be read.
        url: Url,
        source: reqwest::Error,
    },
    /// The downloaded file didn't begin with a known archive magic number.
    UnknownArchive {
        /// Leading bytes of the file, captured for diagnostics.
        first_bytes: Vec<u8>,
    },
    /// Initializing the zstd decoder failed.
    OpenZstd { source: std::io::Error },
    /// Reading the tar archive's entry index failed.
    ScanEntries { source: std::io::Error },
    /// Advancing to the next tar entry failed.
    FetchEntry { source: std::io::Error },
    /// Reading the body of a tar entry (a `desc` file) failed.
    ReadEntry {
        /// Path of the entry inside the archive.
        path: String,
        source: std::io::Error,
    },
    /// The archive contained no usable entries.
    NoEntries,
    /// The largest entry's filename couldn't be joined onto the mirror's URL.
    InvalidLargestEntryUrl {
        /// The offending filename from the archive.
        name: String,
        source: url::ParseError,
    },
}

/// Returns the URL of the largest package in the mirror's `core` repository.
///
/// Downloads the repository database (`CORE_REPO_DIR` + `core.db`) from
/// the given mirror, scans every `desc` entry for its `%CSIZE%`, and returns
/// the URL of the winner.
pub async fn discover(
    client: &reqwest::Client,
    repo_url: &Url,
    time_limit: Duration,
) -> Result<Url, DiscoveryError> {
    let core_db_url = repo_url
        .join(&format!("{CORE_REPO_DIR}core.db"))
        .context(InvalidCoreUrlSnafu)?;
    let response = client
        .get(core_db_url.as_str())
        .timeout(time_limit)
        .send()
        .await
        .context(RequestFailedSnafu {
            url: core_db_url.clone(),
        })?;
    let data = response
        .bytes()
        .await
        .context(DownloadFailedSnafu { url: core_db_url })?
        .to_vec();

    let mut largest_entry = None::<crate::arch_desc::EntryDescription>;

    // Every package contributes one entry shaped like "<pkg-version>/desc";
    // other files in the archive are skipped.
    let mut buf = Vec::<u8>::new();
    let mut archive = tar::Archive::new(open(&data)?);
    for entry in archive.entries().context(ScanEntriesSnafu)? {
        let mut entry = entry.context(FetchEntrySnafu)?;
        if !matches!(entry.header().entry_type(), tar::EntryType::Regular) {
            continue;
        }

        if let Some(path) = entry
            .path()
            .ok()
            .and_then(|entry| entry.to_str().map(str::to_owned))
            && Utf8Path::new(&path).file_name() == Some("desc")
        {
            tracing::debug!("{path}");
            buf.clear();
            entry
                .read_to_end(&mut buf)
                .context(ReadEntrySnafu { path: &path })?;
            match crate::arch_desc::extract_data(&buf) {
                Ok(entry) => {
                    if largest_entry.as_ref().is_none_or(|l| entry.size > l.size) {
                        largest_entry = Some(entry);
                    }
                }
                // A single malformed `desc` shouldn't abort discovery — log
                // and keep scanning for a usable winner.
                Err(e) => tracing::warn!(
                    { path },
                    "Unable to extract desc data: {}",
                    DisplayErrorChain::new(e)
                ),
            }
        }
    }

    let largest_entry = largest_entry.context(NoEntriesSnafu)?;

    tracing::debug!(
        "The largest entry is {}, {} bytes",
        largest_entry.file_name,
        largest_entry.size
    );

    repo_url
        .join(CORE_REPO_DIR)
        .expect("Shouldn't fail")
        .join(&largest_entry.file_name)
        .context(InvalidLargestEntryUrlSnafu {
            name: &largest_entry.file_name,
        })
}

/// Wraps `bytes` in a decoder matching its archive magic number.
///
/// `core.db` ships as either gzip (`1f 8b`) or zstd (`28 b5 2f fd`) compressed
/// tar, depending on which mirror software produced it — we sniff the first
/// bytes rather than relying on the URL extension.
fn open<'a>(bytes: &'a [u8]) -> Result<Box<dyn Read + 'a>, DiscoveryError> {
    match bytes {
        // gzip magic: 1f 8b
        [0x1f, 0x8b, ..] => Ok(Box::new(flate2::read::GzDecoder::new(bytes))),
        // zstd magic: 28 b5 2f fd
        [0x28, 0xb5, 0x2f, 0xfd, ..] => Ok(Box::new(
            zstd::stream::read::Decoder::new(bytes).context(OpenZstdSnafu)?,
        )),
        _ => {
            let first_bytes = bytes.iter().take(5).copied().collect::<Vec<u8>>();
            UnknownArchiveSnafu { first_bytes }.fail()
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::Write as _;

    use super::*;

    /// The sniffing is exercised on real archives, not hand-placed magic
    /// bytes, so a decoder mismatch cannot hide behind a correct prefix.
    #[test]
    fn open_sniffs_gzip_magic() {
        let raw = b"not really a tar, but the decoder does not care";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(raw).unwrap();
        let gz = encoder.finish().unwrap();

        let mut decoded = String::new();
        open(&gz)
            .expect("gzip magic must be recognized")
            .read_to_string(&mut decoded)
            .unwrap();
        assert_eq!(decoded.as_bytes(), raw);
    }

    #[test]
    fn open_sniffs_zstd_magic() {
        let raw = b"same deal, zstd flavour";
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0).unwrap();
        encoder.write_all(raw).unwrap();
        let zst = encoder.finish().unwrap();

        let mut decoded = String::new();
        open(&zst)
            .expect("zstd magic must be recognized")
            .read_to_string(&mut decoded)
            .unwrap();
        assert_eq!(decoded.as_bytes(), raw);
    }

    #[test]
    fn open_rejects_unknown_magic_with_the_leading_bytes() {
        let bogus = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        match open(&bogus) {
            Err(DiscoveryError::UnknownArchive { first_bytes }) => {
                assert_eq!(first_bytes, vec![0x00, 0x01, 0x02, 0x03, 0x04]);
            }
            Err(other) => panic!("unknown magic must be UnknownArchive, got {other:?}"),
            // The Ok arm holds a `dyn Read`, which has no Debug — say so
            // without formatting it.
            Ok(_) => panic!("unknown magic must be UnknownArchive, got Ok"),
        }
    }
}
