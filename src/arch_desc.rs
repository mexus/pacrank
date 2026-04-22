//! Parse the `desc` files that pacman bundles inside `core.db`.
//!
//! Each package in an Archlinux repository ships a small text file named
//! `desc` inside the repo's `.db` tar archive. The file is a sequence of
//! `%KEY%`-headed blocks followed by one or more value lines. We only care
//! about `%FILENAME%` (the on-disk package name) and `%CSIZE%` (the compressed
//! size), enough to pick the largest package for the download test.

use snafu::{OptionExt, ResultExt, Snafu};

/// Subset of an Archlinux package's `desc` metadata: just the fields we need.
#[derive(Debug, Clone)]
pub struct EntryDescription {
    /// Package file name (e.g. `automake-1.18.1-1-any.pkg.tar.zst`).
    pub file_name: String,
    /// Compressed package size, in bytes (pacman's `%CSIZE%` field).
    pub size: u64,
}

/// Errors reported by [`extract_data`].
#[derive(Debug, Snafu)]
pub enum ExtractionError {
    /// The `desc` file didn't contain a `%FILENAME%` block.
    NoFilename,
    /// The `desc` file didn't contain a `%CSIZE%` block.
    NoCompressedSize,
    /// A `%KEY%` header was the last line — its value is missing.
    UnexpectedEof,

    /// A value line wasn't valid UTF-8.
    #[snafu(display("Non-utf8 line after {name}: {:?}", String::from_utf8_lossy(line)))]
    NonUtf8 {
        /// Name of the `%KEY%` whose value failed to decode.
        name: &'static str,
        /// The raw bytes that failed to decode.
        line: Vec<u8>,
        source: std::str::Utf8Error,
    },

    /// A size value wasn't a valid `u64`.
    #[snafu(display("Invalid size after {name}: {value:?}"))]
    InvalidSize {
        /// Name of the `%KEY%` whose value failed to parse.
        name: &'static str,
        /// The raw string we tried to parse.
        value: String,
        source: std::num::ParseIntError,
    },
}

/// Extracts the filename and compressed size from a pacman `desc` blob.
///
/// The file format is a sequence of `%KEY%`-headed blocks separated by blank
/// lines. We only care about `%FILENAME%` and `%CSIZE%`, so other blocks are
/// skipped. Returns an error if either required block is missing or malformed.
pub fn extract_data(contents: &[u8]) -> Result<EntryDescription, ExtractionError> {
    let mut file_name = None::<String>;
    let mut compressed_size = None::<u64>;

    let mut lines = contents
        .split(|byte| *byte == b'\n')
        .map(|line| line.trim_ascii());
    while let Some(current) = lines.next() {
        if current == b"%FILENAME%" {
            let next = lines.next().context(UnexpectedEofSnafu)?;
            let string_value = std::str::from_utf8(next).context(NonUtf8Snafu {
                name: "FILENAME",
                line: next,
            })?;
            file_name = Some(string_value.to_owned());
        } else if current == b"%CSIZE%" {
            let next = lines.next().context(UnexpectedEofSnafu)?;
            let string_value = std::str::from_utf8(next).context(NonUtf8Snafu {
                name: "CSIZE",
                line: next,
            })?;
            let size: u64 = string_value.parse().context(InvalidSizeSnafu {
                value: string_value,
                name: "CSIZE",
            })?;
            compressed_size = Some(size);
        }
    }

    Ok(EntryDescription {
        file_name: file_name.context(NoFilenameSnafu)?,
        size: compressed_size.context(NoCompressedSizeSnafu)?,
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_extract() {
        let data = r#"%FILENAME%
automake-1.18.1-1-any.pkg.tar.zst

%NAME%
automake

%BASE%
automake

%VERSION%
1.18.1-1

%DESC%
A GNU tool for automatically creating Makefiles

%CSIZE%
649767

%ISIZE%
1718030

%SHA256SUM%
47416f72d0d579b391f9be5a55f5b3fa204a09097512b8179d6be5fa0527510a

%PGPSIG%
iQIzBAABCgAdFiEELjbYYgIhSC/EXLfyqRdkdZMmtEAFAmhyUegACgkQqRdkdZMmtEC8NhAAxwg8HSghrdU607+zttCZ3A5xIT63Yv0jQWvVghcvWaBInGu5MIQ+NsmzmptVTOM3/O+i5jDHs/DRYbHX05OSB1F0xkWr+0HwfkrrKsLolfMV7ZMb4NMU5saZQRcglbyXmj1CnNIrQIzjMWTyvVx7d+6tcleOqhvwiAchJrxqqWVAi/kFBTxzjcS2w161mVDwXKm18fsEjSa+RJex+ZnJknikn5Oo15OBShy7kQJroB1jZsKNREeWiaU2mMuCRGuF3DQCsr90lh2HPpti+yMyiM9u5lcPBWjwZ+CfJoRT0qYN6WJZivLV9heC5XAJpL4puL2SytRfQZAi/noQZiqYIvaGyUCmPp5qFw2TPBaKPw58ndf9IREV7dWqfyYhMD3phAnzZje+RYlJ4LZHgqVHBTIy326GbRyUYIIrVBJonXsE5G5Ln5MS6n3GcHUCQH/PkChuZeRthDVObdL2G0jZBhx7AAxkQKQY7LQE95ck3+xVUQ8Whj8n2o5qOE2MH/76f9bF/RhDbTnFbrET41NP1SNp7unnh9vCC6ReBni9Gr5YK3LmG2pFAJcLQs5XRNghoLC4dqppPXGk7p12N1dCldrAFEDvIQ88cRWo9z0wtDubRm553E1pWp8j4UR1n3Ssbsn8ZRW7TUxg5D8z38hY4G2GvA3+XUJmRE2N2CIB5Ls=

%URL%
https://www.gnu.org/software/automake

%LICENSE%
GPL

%ARCH%
any

%BUILDDATE%
1752322329

%PACKAGER%
Lukas Fleischer <lfleischer@archlinux.org>

%DEPENDS%
perl
bash

%MAKEDEPENDS%
autoconf
git

%CHECKDEPENDS%
dejagnu
gcc-fortran
java-environment
vala
emacs
cscope
expect
ncompress
gettext
lzip
zip
sharutils
help2man
python
python-virtualenv
"#;
        let EntryDescription { file_name, size } = extract_data(data.as_bytes()).unwrap();
        assert_eq!(file_name, "automake-1.18.1-1-any.pkg.tar.zst");
        assert_eq!(size, 649_767);
    }
}
