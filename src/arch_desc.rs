use snafu::{OptionExt, ResultExt, Snafu};

/// Archlinux repository entry description.
#[derive(Debug, Clone)]
pub struct EntryDescription {
    /// File name.
    pub file_name: String,
    /// Compressed size.
    pub size: u64,
}

#[derive(Debug, Snafu)]
pub enum ExtractionError {
    NoFilename,
    NoCompressedSize,
    UnexpectedEof,

    #[snafu(display("Non-utf8 line after {name}: {:?}", String::from_utf8_lossy(line)))]
    NonUtf8 {
        name: &'static str,
        line: Vec<u8>,
        source: std::str::Utf8Error,
    },

    #[snafu(display("Invalid size after {name}: {value:?}"))]
    InvalidSize {
        name: &'static str,
        value: String,
        source: std::num::ParseIntError,
    },
}

/// Extracts some data from a 'desc' contents.
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
