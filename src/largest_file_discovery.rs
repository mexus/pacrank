//! Discover the largest file in an Archlinux repo

use std::io::Read;

use camino::Utf8Path;
use display_error_chain::DisplayErrorChain;
use snafu::{OptionExt, ResultExt, Snafu};
use url::Url;

#[derive(Debug, Snafu)]
pub enum DiscoveryError {
    InvalidCoreUrl {
        source: url::ParseError,
    },
    RequestFailed {
        url: Url,
        source: reqwest::Error,
    },
    DownloadFailed {
        url: Url,
        source: reqwest::Error,
    },
    UnknownArchive {
        first_bytes: Vec<u8>,
    },
    OpenZstd {
        source: std::io::Error,
    },
    ScanEntries {
        source: std::io::Error,
    },
    FetchEntry {
        source: std::io::Error,
    },
    ReadEntry {
        path: String,
        source: std::io::Error,
    },
    NoEntries,
    InvalidLargestEntryUrl {
        name: String,
        source: url::ParseError,
    },
}

pub async fn discover(client: &reqwest::Client, repo_url: &Url) -> Result<Url, DiscoveryError> {
    let core_db_url = repo_url
        .join("core/os/x86_64/core.db")
        .context(InvalidCoreUrlSnafu)?;
    let response = client
        .get(core_db_url.as_str())
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
                    if let Some(largest_entry) = &mut largest_entry {
                        if entry.size > largest_entry.size {
                            *largest_entry = entry;
                        }
                    } else {
                        largest_entry = Some(entry)
                    }
                }
                Err(e) => tracing::warn!(
                    { path },
                    "Unable to extract desc data: {}",
                    DisplayErrorChain::new(e)
                ),
            }
            // "python-brotli-1.2.0-1/desc"
        }
    }

    let largest_entry = largest_entry.context(NoEntriesSnafu)?;

    tracing::debug!(
        "The largest entry is {}, {} bytes",
        largest_entry.file_name,
        largest_entry.size
    );

    repo_url
        .join("core/os/x86_64/")
        .expect("Shouldn't fail")
        .join(&largest_entry.file_name)
        .context(InvalidLargestEntryUrlSnafu {
            name: &largest_entry.file_name,
        })
}

fn open<'a>(bytes: &'a [u8]) -> Result<Box<dyn Read + 'a>, DiscoveryError> {
    match bytes {
        [0x1f, 0x8b, ..] => Ok(Box::new(flate2::read::GzDecoder::new(bytes))),
        [0x28, 0xb5, 0x2f, 0xfd, ..] => Ok(Box::new(
            zstd::stream::read::Decoder::new(bytes).context(OpenZstdSnafu)?,
        )),
        _ => {
            let first_bytes = bytes.iter().take(5).copied().collect::<Vec<u8>>();
            UnknownArchiveSnafu { first_bytes }.fail()
        }
    }
}
