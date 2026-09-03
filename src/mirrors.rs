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
    ///
    /// Deserialized leniently: see [`lenient_mirrors`].
    #[serde(deserialize_with = "lenient_mirrors")]
    pub urls: Vec<Mirror>,

    /// Last check time.
    #[serde(with = "time::serde::iso8601")]
    pub last_check: time::OffsetDateTime,
}

/// Deserializes the mirror list, dropping entries that fail to parse instead
/// of failing the list as a whole.
///
/// A single bad entry — an URL the `url` crate rejects, a timestamp in an
/// unexpected shape — would otherwise cost us all thousand-odd mirrors. Since
/// every entry is independent, skipping the offender (loudly) is always the
/// better trade.
fn lenient_mirrors<'de, D>(deserializer: D) -> Result<Vec<Mirror>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw: Vec<serde_json::Value> = serde::Deserialize::deserialize(deserializer)?;
    Ok(raw
        .into_iter()
        .filter_map(|entry| {
            let url = entry
                .get("url")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<no url>")
                .to_owned();
            match serde_json::from_value(entry) {
                Ok(mirror) => Some(mirror),
                Err(e) => {
                    tracing::warn!("Skipping unparseable mirror entry {url}: {e}");
                    None
                }
            }
        })
        .collect())
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
    ///
    /// Can be negative when the mirror's reported sync timestamp is ahead of
    /// the check time (clock skew on the mirror's side), so it must not be
    /// deserialized as an unsigned integer.
    pub delay: Option<i64>,

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
            /// All known variants, in declaration order. Excludes `Unknown`.
            pub const ALL: &'static [Self] = &[ $(Self::$code,)* ];

            /// Return all known country codes.
            pub fn all() -> impl ExactSizeIterator<Item = Self> {
                Self::ALL.iter().copied()
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

        impl clap::ValueEnum for $container {
            fn value_variants<'a>() -> &'a [Self] {
                Self::ALL
            }

            fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
                match self {
                    // `Unknown` is for deserializing mirrors that report an
                    // exotic country — we must not let users type it in.
                    Self::Unknown => None,
                    _ => Some(clap::builder::PossibleValue::new(self.as_code())),
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
///
/// Upstream derives this from the mirror URL's scheme and stores it in a
/// lookup table an admin can extend, so the set isn't closed; unrecognized
/// values deserialize to [`Protocol::Unknown`] rather than failing.
#[derive(Debug, serde::Deserialize, serde::Serialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// HTTP protocol.
    Http,
    /// HTTPS protocol.
    Https,
    /// Rsync protocol.
    Rsync,

    /// A protocol this version doesn't know about.
    #[serde(other)]
    Unknown,
}

impl Mirror {
    /// Whether pacman can fetch from this mirror over plain HTTP(S).
    ///
    /// Rsync mirrors are usable through separate tooling, but not via the
    /// `Server = ...` lines this tool writes; neither are protocols we don't
    /// recognize. Both must be filtered out.
    pub fn is_http(&self) -> bool {
        matches!(self.protocol, Protocol::Http | Protocol::Https)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    /// A trimmed-down excerpt of the real `mirrors/status/json/` payload,
    /// salted with the entry shapes that used to abort parsing of the *whole*
    /// list: a negative `delay` (entry 2, taken verbatim from a live mirror),
    /// an unknown `protocol` (entry 3) and an URL without a scheme (entry 4).
    const MIRRORS_EXCERPT: &str = r#"{
        "cutoff": 86400,
        "last_check": "2026-09-03T09:05:12.086Z",
        "num_checks": 25,
        "check_frequency": 3600,
        "urls": [
            {
                "url": "https://mirror.aarnet.edu.au/pub/archlinux/",
                "protocol": "https",
                "last_sync": "2026-09-03T08:22:00Z",
                "completion_pct": 1.0,
                "delay": 1749,
                "duration_avg": 0.9830624709526697,
                "duration_stddev": 0.213086265106851,
                "score": 1.681982069392854,
                "active": true,
                "country": "Australia",
                "country_code": "AU",
                "isos": true,
                "ipv4": true,
                "ipv6": true,
                "details": "https://archlinux.org/mirrors/aarnet.edu.au/5/"
            },
            {
                "url": "http://repository.su/archlinux/",
                "protocol": "http",
                "last_sync": "2026-09-03T08:30:03Z",
                "completion_pct": 1.0,
                "delay": -33,
                "duration_avg": 0.1788191944360733,
                "duration_stddev": 0.20379207106597516,
                "score": 0.37344459883538306,
                "active": true,
                "country": "Russia",
                "country_code": "RU",
                "isos": true,
                "ipv4": true,
                "ipv6": false,
                "details": "https://archlinux.org/mirrors/repository.su/1507/"
            },
            {
                "url": "ftp://mirror.example.net/archlinux/",
                "protocol": "ftp",
                "last_sync": "2026-09-03T07:58:11Z",
                "completion_pct": 1.0,
                "delay": 900,
                "duration_avg": 0.5,
                "duration_stddev": 0.1,
                "score": 1.5,
                "active": true,
                "country": "Germany",
                "country_code": "DE",
                "isos": true,
                "ipv4": true,
                "ipv6": true,
                "details": "https://archlinux.org/mirrors/example.net/2/"
            },
            {
                "url": "mirror.example.com/archlinux/",
                "protocol": "https",
                "last_sync": "2026-09-03T08:11:47Z",
                "completion_pct": 1.0,
                "delay": 500,
                "duration_avg": 0.3,
                "duration_stddev": 0.1,
                "score": 0.9,
                "active": true,
                "country": "France",
                "country_code": "FR",
                "isos": true,
                "ipv4": true,
                "ipv6": true,
                "details": "https://archlinux.org/mirrors/example.com/3/"
            },
            {
                "url": "rsync://mirror.example.org/archlinux/",
                "protocol": "rsync",
                "last_sync": null,
                "completion_pct": 0.0,
                "delay": null,
                "duration_avg": null,
                "duration_stddev": null,
                "score": null,
                "active": false,
                "country": "",
                "country_code": "",
                "isos": false,
                "ipv4": true,
                "ipv6": false,
                "details": "https://archlinux.org/mirrors/example.org/1/"
            }
        ],
        "version": 3
    }"#;

    /// Mirrors whose clock runs ahead of the check server report a negative
    /// delay; that must not break parsing of the list.
    #[test]
    fn parse_negative_delay() {
        let Mirrors::V3(mirrors) =
            serde_json::from_str(MIRRORS_EXCERPT).expect("Must parse the mirrors excerpt");

        let by_delay: Vec<_> = mirrors.urls.iter().map(|m| m.delay).collect();
        assert_eq!(by_delay, [Some(1749), Some(-33), Some(900), None]);

        let negative = &mirrors.urls[1];
        assert_eq!(negative.country_code, CountryCode::RU);
        assert_eq!(negative.protocol, Protocol::Http);
        assert!(negative.is_http());
    }

    /// The `protocol` field is an open-ended lookup upstream (it's derived
    /// from the URL scheme), so an unfamiliar value must not fail the list —
    /// and must not slip past the HTTP(S) filter either.
    #[test]
    fn parse_unknown_protocol() {
        let Mirrors::V3(mirrors) =
            serde_json::from_str(MIRRORS_EXCERPT).expect("Must parse the mirrors excerpt");

        let ftp = &mirrors.urls[2];
        assert_eq!(ftp.protocol, Protocol::Unknown);
        assert_eq!(ftp.country_code, CountryCode::DE);
        assert!(
            !ftp.is_http(),
            "An unknown protocol must never reach the mirrorlist"
        );

        // Rsync is known, and equally unusable over HTTP.
        let rsync = &mirrors.urls[3];
        assert_eq!(rsync.protocol, Protocol::Rsync);
        assert!(!rsync.is_http());
        assert_eq!(rsync.country_code, CountryCode::Unknown);
        assert!(rsync.last_sync.is_none());
    }

    /// An entry the `url` crate rejects costs us that one mirror, not all of
    /// them.
    #[test]
    fn skip_unparseable_entries() {
        let Mirrors::V3(mirrors) =
            serde_json::from_str(MIRRORS_EXCERPT).expect("Must parse the mirrors excerpt");

        assert_eq!(mirrors.urls.len(), 4, "The scheme-less URL must be dropped");
        assert!(
            !mirrors
                .urls
                .iter()
                .any(|m| m.url.as_str().contains("example.com")),
            "The scheme-less URL must not be parsed into something else"
        );
    }

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
