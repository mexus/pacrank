//! Mirror-related utilities.

/// Version-aware mirrors list.
#[derive(Debug, Clone)]
pub enum Mirrors {
    /// Mirrors version 3.
    V3(
        /// The mirrors.
        MirrorsV3,
    ),
}

impl<'de> serde::Deserialize<'de> for Mirrors {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct WithVersion {
            version: u32,
            #[serde(flatten, default)]
            remainder: serde_json::Value,
        }

        let WithVersion { version, remainder } = WithVersion::deserialize(deserializer)?;

        match version {
            3 => {
                let mirrors: MirrorsV3 = serde_json::from_value(remainder)
                    .map_err(<D::Error as serde::de::Error>::custom)?;
                Ok(Self::V3(mirrors))
            }
            _ => Err(<D::Error as serde::de::Error>::custom(format!(
                "Unsupported mirror list version {version}"
            ))),
        }
    }
}

impl serde::Serialize for Mirrors {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(serde::Serialize)]
        struct WithVersion<'a> {
            #[serde(flatten)]
            inner: &'a MirrorsV3,
            version: u32,
        }

        match self {
            Mirrors::V3(mirrors_v3) => serde::Serialize::serialize(
                &WithVersion {
                    inner: mirrors_v3,
                    version: 3,
                },
                serializer,
            ),
        }
    }
}

/// Archlinux mirrors info.
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct MirrorsV3 {
    /// The actual list of mirrors.
    pub urls: Vec<Mirror>,

    /// Last check time.
    #[serde(with = "time::serde::iso8601")]
    pub last_check: time::OffsetDateTime,
}

/// Archlinux mirror info.
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct Mirror {
    /// Mirror URL.
    pub url: url::Url,

    /// Communication protocol.
    pub protocol: Protocol,

    /// Reported country.
    pub country_code: CountryCode,

    /// Delay (seconds).
    pub delay: Option<u64>,

    /// Last sync time.
    #[serde(with = "serde_maybe_time")]
    pub last_sync: Option<time::OffsetDateTime>,
}

/// Serde helpers for `Option<OffsetDateTime>` fields encoded as ISO-8601.
///
/// The `time` crate's built-in `time::serde::iso8601` only handles the
/// non-optional case; this module wraps it to also accept `null`.
pub(crate) mod serde_maybe_time {
    use serde::{Deserializer, Serializer};
    use time::OffsetDateTime;

    /// Serializes `Some(datetime)` as an ISO-8601 string and `None` as `null`.
    pub fn serialize<S>(datetime: &Option<OffsetDateTime>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(datetime) = datetime {
            time::serde::iso8601::serialize(datetime, serializer)
        } else {
            serializer.serialize_none()
        }
    }

    /// Deserializes `null` as `None` and any ISO-8601 string as `Some(dt)`.
    pub fn deserialize<'a, D>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error>
    where
        D: Deserializer<'a>,
    {
        struct MaybeVisitor;
        impl<'de> serde::de::Visitor<'de> for MaybeVisitor {
            type Value = Option<OffsetDateTime>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("null or iso8601 date time string")
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                time::serde::iso8601::deserialize(deserializer).map(Some)
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(None)
            }
        }
        deserializer.deserialize_option(MaybeVisitor)
    }
}

/// Defines a country-code enum with `as_code`, `full_name`, `all`, `FromStr`
/// and `Display` impls from a `CODE => "Full Name"` list.
///
/// Unknown codes (including the empty string) deserialize to `Unknown` rather
/// than failing, so mirrors reporting exotic country codes don't break
/// parsing of the whole list.
macro_rules! countries {
    ( $container:ident: $( $code:ident => $full_name:literal ),* $(,)? ) => {
        /// Known countries.
        #[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
        pub enum $container {
            $(
                #[doc = $full_name]
                $code,
            )*

            /// Unknown or unspecified country.
            #[serde(other)]
            Unknown,
        }

        impl $container {
            /// Return all known country codes.
            pub fn all() -> impl ExactSizeIterator<Item = Self> {
                [ $(Self::$code,)* ].into_iter()
            }

            /// Returns a human-readable country name.
            pub fn full_name(&self) -> &'static str {
                match self {
                    $( Self::$code => $full_name, )*
                    Self::Unknown => "[unknown]",
                }
            }

            /// Returns a short country code.
            pub fn as_code(&self) -> &'static str {
                match self {
                    $( Self::$code => stringify!($code), )*
                    Self::Unknown => "",
                }
            }
        }

        impl std::str::FromStr for $container {
            type Err = std::convert::Infallible;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(match s {
                    $( stringify!($code) => Self::$code, )*
                    _ => Self::Unknown
                })
            }
        }

        impl std::fmt::Display for $container {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(self.as_code(), f)
            }
        }
    };
}

// Define the known countries.
countries!(CountryCode:
    AE => "United Arab Emirates",
    AL => "Albania",
    AM => "Armenia",
    AT => "Austria",
    AU => "Australia",
    AZ => "Azerbaijan",
    BD => "Bangladesh",
    BE => "Belgium",
    BG => "Bulgaria",
    BR => "Brazil",
    BY => "Belarus",
    CA => "Canada",
    CH => "Switzerland",
    CL => "Chile",
    CN => "China",
    CO => "Colombia",
    CZ => "Czechia",
    DE => "Germany",
    DK => "Denmark",
    EC => "Ecuador",
    EE => "Estonia",
    ES => "Spain",
    FI => "Finland",
    FR => "France",
    GB => "United Kingdom",
    GE => "Georgia",
    GR => "Greece",
    HK => "Hong Kong",
    HR => "Croatia",
    HU => "Hungary",
    ID => "Indonesia",
    IL => "Israel",
    IN => "India",
    IR => "Iran",
    IS => "Iceland",
    IT => "Italy",
    JP => "Japan",
    KE => "Kenya",
    KH => "Cambodia",
    KR => "South Korea",
    KZ => "Kazakhstan",
    LT => "Lithuania",
    LU => "Luxembourg",
    LV => "Latvia",
    MA => "Morocco",
    MD => "Moldova",
    MK => "North Macedonia",
    MU => "Mauritius",
    MX => "Mexico",
    MY => "Malaysia",
    NC => "New Caledonia",
    NL => "Netherlands",
    NO => "Norway",
    NP => "Nepal",
    NZ => "New Zealand",
    PL => "Poland",
    PT => "Portugal",
    PY => "Paraguay",
    RE => "Réunion",
    RO => "Romania",
    RS => "Serbia",
    RU => "Russia",
    SA => "Saudi Arabia",
    SE => "Sweden",
    SG => "Singapore",
    SI => "Slovenia",
    SK => "Slovakia",
    TH => "Thailand",
    TR => "Türkiye",
    TW => "Taiwan",
    UA => "Ukraine",
    US => "United States",
    UZ => "Uzbekistan",
    VN => "Vietnam",
    ZA => "South Africa",
);

/// Known protocols.
#[derive(Debug, serde::Deserialize, serde::Serialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// HTTP protocol.
    Http,
    /// HTTPS protocol.
    Https,
    /// Rsync protocol.
    Rsync,
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    #[test]
    fn country_parse() {
        let codes = CountryCode::all();
        for code in codes {
            let code_str = code.as_code();
            let code_parsed = code_str.parse().expect("Must be ok");
            assert_eq!(code, code_parsed, "code_str = {code_str}");

            let code_fmt = code.to_string();
            let code_parsed = code_fmt.parse().expect("Must be ok");
            assert_eq!(code, code_parsed, "code_fmt = {code_fmt}");
        }
    }
}
