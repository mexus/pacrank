//! Mirror-related utilities.

use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use display_error_chain::DisplayErrorChain;

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

/// Archlinux mirrors info.
#[derive(Debug, serde::Deserialize, Clone)]
pub struct MirrorsV3 {
    /// The actual list of mirrors.
    ///
    /// Deserialized leniently: see `lenient_mirrors`.
    #[serde(deserialize_with = "lenient_mirrors")]
    pub urls: Vec<Mirror>,
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
#[derive(Debug, serde::Deserialize, Clone)]
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
    #[serde(with = "time::serde::iso8601::option")]
    pub last_sync: Option<time::OffsetDateTime>,
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

impl CountryCode {
    /// Removes repeated country codes, keeping the first occurrence of each.
    ///
    /// The order carries meaning — auto-detection yields the closest country
    /// first — so this deliberately isn't a `sort` + `dedup`.
    pub fn dedup(countries: &mut Vec<Self>) {
        let mut seen = HashSet::with_capacity(countries.len());
        countries.retain(|country| seen.insert(*country));
    }

    /// Renders a list of countries for log output as `Name (CODE), …`.
    ///
    /// The code is worth the extra width: it's what the reader would type
    /// back into `-c` to pin the result. `Unknown` has no code to show, so it
    /// renders as its name alone.
    pub fn format_list(countries: &[Self]) -> String {
        countries
            .iter()
            .map(|country| match country {
                Self::Unknown => country.full_name().to_string(),
                _ => format!("{} ({})", country.full_name(), country.as_code()),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Known protocols.
///
/// Upstream derives this from the mirror URL's scheme and stores it in a
/// lookup table an admin can extend, so the set isn't closed; unrecognized
/// values deserialize to [`Protocol::Unknown`] rather than failing.
#[derive(Debug, serde::Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
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

    /// The mirror's `lastsync` URL — cheap to HEAD and present on every
    /// mirror, which makes it the probe target for both the survey and the
    /// latency phase.
    pub fn lastsync_url(&self) -> Result<url::Url, url::ParseError> {
        self.url.join("lastsync")
    }

    /// Whether this mirror synced within [`FRESHNESS_WINDOW`], reports a
    /// plausible delay, and serves over HTTP(S) — the gate both the survey
    /// and the discovery pipeline apply before probing a mirror.
    pub fn is_fresh(&self) -> bool {
        let oldest_sync = time::OffsetDateTime::now_utc() - FRESHNESS_WINDOW;
        self.is_http()
            && self.last_sync.is_some_and(|ts| ts >= oldest_sync)
            && self
                .delay
                .is_some_and(|d| d <= FRESHNESS_WINDOW.as_secs() as i64)
    }
}

/// The first mirror of each distinct hostname, in input order.
///
/// `http://X` and `https://X` are two mirrors but one machine, so any stage
/// that resolves or probes hosts wants each name once, keeping the first
/// entry it sees. A mirror without a hostname at all never makes the cut —
/// neither consumer can do anything with it.
pub(crate) fn distinct_by_host<'a, I>(mirrors: I) -> Vec<&'a Mirror>
where
    I: IntoIterator<Item = &'a Mirror>,
{
    let mut seen = HashSet::new();
    mirrors
        .into_iter()
        .filter(|mirror| {
            mirror
                .url
                .host_str()
                .is_some_and(|host| seen.insert(host.to_owned()))
        })
        .collect()
}

/// How recent a mirror's last sync must be for either stage to consider it.
///
/// 48 h is a loose freshness gate: a mirror briefly behind during its own
/// sync cycle might still be the fastest, so the cutoff must not be tight.
/// Anything staler than that is almost certainly broken.
pub const FRESHNESS_WINDOW: Duration = Duration::from_hours(48);

/// Endpoint carrying the official mirror status document.
const STATUS_URL: &str = "https://archlinux.org/mirrors/status/json/";

/// How long one attempt at fetching the mirror status document may take in
/// total.
///
/// The document is a few MB of JSON, so the bound has to be generous
/// enough for a slow uplink to land it — but it must exist: this is the
/// first network action of both the survey and the pipeline, and without
/// it a stalled archlinux.org response (the shared client sets only a
/// connect timeout) would hang the run before anything else happens.
///
/// Generous is the operative word, because this endpoint is a single point
/// of failure: nothing downstream can run without it, so the cost of
/// waiting is a slow run while the cost of giving up early is no run at
/// all. With [`FETCH_ATTEMPTS`] and [`RETRY_BACKOFF`] the whole ladder is
/// bounded at roughly a minute and a half before the run is declared dead.
///
/// Note what this bound does *not* cover: establishing the connection is
/// capped separately, and a total timeout can only ever be the outer of the
/// two — see [`STATUS_CONNECT_TIMEOUT`].
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the mirror-list client waits for its TCP (+ TLS) connection.
///
/// A connect timeout is a client-wide setting in reqwest — `RequestBuilder`
/// offers only the total [`FETCH_TIMEOUT`] — so raising the total alone
/// leaves the handshake pinned to whatever the client was built with, and
/// the shared client is built for *measuring mirrors*
/// (`crate::CONNECT_TIMEOUT`, 2s). That is why [`fetch`] builds its own
/// client: this request is the run's prerequisite, and an archlinux.org
/// handshake that takes four seconds on a congested uplink is a slow run,
/// not a failed one.
///
/// 10s sits an order of magnitude above the normal handshake (~300ms to the
/// CDN) and still an order below [`FETCH_TIMEOUT`], so a connect that is
/// merely slow is absorbed while one that is truly hung still leaves the
/// attempt room to be retried.
const STATUS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How many times the mirror status document may be requested before the
/// run gives up on it.
///
/// Only failures that [`is_retryable`] accepts consume an attempt beyond the
/// first, so a permanently broken answer still costs exactly one request.
///
/// More than one attempt is not paranoia. A run on 2026-09-16, back when
/// this fetch still borrowed the measurement client's 2s connect cap, lost
/// two attempts in a row to that timeout and landed the document on the
/// third — a run that, with a single attempt, dies before it starts.
/// [`STATUS_CONNECT_TIMEOUT`] is the answer to that particular failure;
/// the attempts are the answer to the general one, since a lost packet or a
/// front end mid-restart does not care how patient a single attempt is.
const FETCH_ATTEMPTS: u32 = 3;

/// Base delay before a retry; doubled per attempt.
///
/// Unjittered, unlike [`crate::dns`]'s ladder: that one spreads a burst of
/// concurrent lookups off each other, whereas this is one request to one
/// host, with nothing to collide with.
const RETRY_BACKOFF: Duration = Duration::from_secs(1);

/// Fetches the current mirror status document, retrying a transient
/// failure up to [`FETCH_ATTEMPTS`] times.
///
/// Both consumers of the list — the country survey and the discovery
/// pipeline — read this one endpoint; sharing the fetch keeps the URL (and
/// the lenient parse behavior below it) single-sourced.
///
/// Takes the resolver rather than a ready client because the connect budget
/// is part of what this operation is (see [`STATUS_CONNECT_TIMEOUT`]) and
/// reqwest can only express it at client level. The resolver is still the
/// caller's own, so the name is looked up once for the whole run; only the
/// connection pool is private to this request.
pub async fn fetch(resolver: &crate::dns::SurveyResolver) -> Result<Mirrors, reqwest::Error> {
    let client = crate::build_client_with(resolver.clone(), STATUS_CONNECT_TIMEOUT)?;
    fetch_from(&client, STATUS_URL, RETRY_BACKOFF).await
}

/// The body of [`fetch`], with the endpoint and the backoff base as
/// parameters so the tests can drive it against a local server without
/// sitting through the real ladder.
async fn fetch_from(
    client: &reqwest::Client,
    url: &str,
    backoff_base: Duration,
) -> Result<Mirrors, reqwest::Error> {
    let mut attempt = 1;
    loop {
        tracing::info!("Fetching the mirror list from {url} (attempt {attempt}/{FETCH_ATTEMPTS})");
        let started = Instant::now();
        let error = match fetch_once(client, url).await {
            Ok(mirrors) => {
                tracing::info!(
                    "Fetched the mirror list in {:.2?} (attempt {attempt}/{FETCH_ATTEMPTS})",
                    started.elapsed()
                );
                return Ok(mirrors);
            }
            Err(error) => error,
        };
        let elapsed = started.elapsed();
        let chain = DisplayErrorChain::new(&error);
        if !is_retryable(&error) {
            tracing::warn!(
                "Attempt {attempt}/{FETCH_ATTEMPTS} at the mirror list failed after {elapsed:.2?} \
                 and asking again cannot help: {chain}"
            );
            return Err(error);
        }
        if attempt == FETCH_ATTEMPTS {
            tracing::warn!(
                "Attempt {attempt}/{FETCH_ATTEMPTS} at the mirror list failed after \
                 {elapsed:.2?}, out of attempts: {chain}"
            );
            return Err(error);
        }
        let backoff = backoff_base * (1 << (attempt - 1));
        tracing::warn!(
            "Attempt {attempt}/{FETCH_ATTEMPTS} at the mirror list failed after {elapsed:.2?}, \
             retrying in {backoff:.2?}: {chain}"
        );
        tokio::time::sleep(backoff).await;
        attempt += 1;
    }
}

/// One request for the status document.
///
/// `error_for_status` is what keeps a 5xx from reaching the parser and
/// surfacing as "expected value at line 1" — the status is both the honest
/// diagnosis and the thing [`is_retryable`] reads.
async fn fetch_once(client: &reqwest::Client, url: &str) -> Result<Mirrors, reqwest::Error> {
    client
        .get(url)
        .timeout(FETCH_TIMEOUT)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
}

/// Whether requesting the document again could plausibly change the answer.
///
/// A body that isn't the document we understand is a verdict, not an
/// accident: it arrived intact, and re-downloading a few megabytes to parse
/// them exactly the same way only delays the error the user needs to see. A
/// 4xx is the same kind of answer from the other side. Everything else — a
/// refused connection, a transfer cut mid-body, a timeout, a 5xx from an
/// overloaded front end — is precisely what the retry exists for.
fn is_retryable(error: &reqwest::Error) -> bool {
    !error.is_decode()
        && !error
            .status()
            .is_some_and(|status| status.is_client_error())
}

#[cfg(test)]
pub(crate) mod test {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

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

    #[test]
    fn dedup_keeps_the_first_occurrence() {
        let mut countries = vec![
            CountryCode::RU,
            CountryCode::CN,
            CountryCode::RU,
            CountryCode::CN,
            CountryCode::DE,
        ];
        CountryCode::dedup(&mut countries);
        assert_eq!(
            countries,
            vec![CountryCode::RU, CountryCode::CN, CountryCode::DE]
        );
    }

    #[test]
    fn format_list_spells_out_the_names() {
        assert_eq!(
            CountryCode::format_list(&[CountryCode::RU, CountryCode::CN]),
            "Russia (RU), China (CN)"
        );
        assert_eq!(CountryCode::format_list(&[]), "");
        // The codeless variant must not render as `[unknown] ()`.
        assert_eq!(
            CountryCode::format_list(&[CountryCode::Unknown]),
            "[unknown]"
        );
    }

    #[test]
    fn dedup_leaves_a_unique_list_alone() {
        let mut countries = vec![CountryCode::DE, CountryCode::NL, CountryCode::AT];
        let expected = countries.clone();
        CountryCode::dedup(&mut countries);
        assert_eq!(countries, expected);
    }

    /// A fresh mirror fixture; every field is overridable through the
    /// arguments so each predicate case reads as its one difference from
    /// the defaults.
    fn fresh_mirror(
        protocol: Protocol,
        last_sync: Option<time::OffsetDateTime>,
        delay: Option<i64>,
    ) -> Mirror {
        Mirror {
            url: "https://mirror.example.com/archlinux/".parse().unwrap(),
            protocol,
            country_code: CountryCode::DE,
            delay,
            last_sync,
        }
    }

    fn hours_ago(n: i64) -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc() - time::Duration::hours(n)
    }

    /// The shared gate both stages filter by — cheap to pin exhaustively,
    /// load-bearing to get right: it decides what the whole tool is allowed
    /// to rank.
    #[test]
    fn is_fresh_gate() {
        let http = fresh_mirror(Protocol::Http, Some(hours_ago(1)), Some(60));
        assert!(http.is_fresh(), "a plain healthy HTTP mirror passes");

        // Missing either timestamp or delay: not decidable, dropped.
        assert!(!fresh_mirror(Protocol::Https, None, Some(60)).is_fresh());
        assert!(!fresh_mirror(Protocol::Https, Some(hours_ago(1)), None).is_fresh());

        // Non-HTTP protocols never reach the mirrorlist. Ftp only ever
        // arrives as `Protocol::Unknown` after deserialization, but the
        // predicate's answer is the same for any non-HTTP variant.
        assert!(!fresh_mirror(Protocol::Rsync, Some(hours_ago(1)), Some(60)).is_fresh());
        assert!(!fresh_mirror(Protocol::Unknown, Some(hours_ago(1)), Some(60)).is_fresh());

        // Stale syncs and long delays are the two halves of the 48h window.
        assert!(fresh_mirror(Protocol::Https, Some(hours_ago(47)), Some(60)).is_fresh());
        assert!(!fresh_mirror(Protocol::Https, Some(hours_ago(49)), Some(60)).is_fresh());
        assert!(!fresh_mirror(Protocol::Https, Some(hours_ago(1)), Some(172_801)).is_fresh());

        // The boundaries are inclusive by design (`>=`/`<=`): a mirror
        // exactly on the line is kept. Delay is checked against a constant,
        // so the boundary is exact; a timestamp on the line would race
        // `now_utc()` between fixture and call, hence 47h/49h above.
        assert!(fresh_mirror(Protocol::Https, Some(hours_ago(1)), Some(172_800)).is_fresh());

        // Negative delays are real (clock-skewed mirrors) and pass the `<=`
        // comparison, like the live `repository.su` entry.
        assert!(fresh_mirror(Protocol::Https, Some(hours_ago(1)), Some(-33)).is_fresh());

        // A future timestamp (skew in the other direction) is not stale.
        assert!(fresh_mirror(Protocol::Https, Some(hours_ago(-1)), Some(60)).is_fresh());
    }

    /// First mirror per hostname, in input order — the collapse both stages
    /// apply before resolving or probing.
    #[test]
    fn distinct_by_host_keeps_first_seen_order() {
        let twins = |scheme: &str| {
            format!("{scheme}://mirror.example.com/archlinux/")
                .parse()
                .unwrap()
        };
        let mut http_twin = fresh_mirror(Protocol::Http, Some(hours_ago(1)), Some(60));
        http_twin.url = twins("http");
        let mut https_twin = fresh_mirror(Protocol::Https, Some(hours_ago(1)), Some(60));
        https_twin.url = twins("https");
        let mut other = fresh_mirror(Protocol::Https, Some(hours_ago(1)), Some(60));
        other.url = "https://other.example.org/archlinux/".parse().unwrap();
        let mut hostless = fresh_mirror(Protocol::Https, Some(hours_ago(1)), Some(60));
        hostless.url = "data:mirror/example".parse().unwrap();

        let kept = distinct_by_host([&http_twin, &https_twin, &other, &hostless]);
        assert_eq!(
            kept.iter().map(|m| m.url.as_str()).collect::<Vec<_>>(),
            [
                "http://mirror.example.com/archlinux/",
                "https://other.example.org/archlinux/"
            ],
            "one entry per host, the first one seen; a hostless mirror never makes the cut"
        );
    }

    /// The version dispatch behind `Mirrors`' custom Deserialize: only v3
    /// parses, and both an unknown version and a missing one say so.
    #[test]
    fn version_dispatch() {
        let Mirrors::V3(mirrors) =
            serde_json::from_str(MIRRORS_EXCERPT).expect("version 3 must parse");
        assert_eq!(mirrors.urls.len(), 4);

        let v4 = MIRRORS_EXCERPT.replace("\"version\": 3", "\"version\": 4");
        let err =
            serde_json::from_str::<Mirrors>(&v4).expect_err("an unknown version must be rejected");
        assert!(
            err.to_string().contains("version 4"),
            "the error should name the version: {err}"
        );

        let versionless = MIRRORS_EXCERPT.replace(",\n        \"version\": 3", "");
        assert!(
            serde_json::from_str::<Mirrors>(&versionless).is_err(),
            "a missing version must be rejected"
        );
    }

    /// Base backoff for the retry tests: the ladder's shape is what's under
    /// test, not its patience.
    const TEST_BACKOFF: Duration = Duration::from_millis(10);

    /// Serves one response per connection, `respond(hit)` deciding what the
    /// `hit`-th request gets; `None` drops the connection unanswered, the
    /// shape of a front end cutting a transfer off. Returns the bound
    /// address and the live request count.
    async fn spawn_scripted_server<F>(respond: F) -> (std::net::SocketAddr, Arc<AtomicUsize>)
    where
        F: Fn(usize) -> Option<String> + Send + Sync + 'static,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let served = Arc::clone(&hits);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                // Every response below closes the connection, so one accept
                // is one request and the count needs no parsing to be right.
                let response = respond(served.fetch_add(1, Ordering::SeqCst));
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    if let Some(response) = response {
                        let _ = sock.write_all(response.as_bytes()).await;
                    }
                });
            }
        });
        (addr, hits)
    }

    fn http_response(status_line: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status_line}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// The failure the retry exists for: the first attempt is cut off, the
    /// second lands the document. A single blip must not cost the run.
    #[tokio::test]
    async fn a_cut_off_fetch_is_retried() {
        let (addr, hits) = spawn_scripted_server(|hit| {
            (hit > 0).then(|| http_response("200 OK", MIRRORS_EXCERPT))
        })
        .await;

        let Mirrors::V3(mirrors) = fetch_from(
            &reqwest::Client::new(),
            &format!("http://{addr}/"),
            TEST_BACKOFF,
        )
        .await
        .expect("the second attempt must land the document");

        assert_eq!(mirrors.urls.len(), 4);
        assert_eq!(hits.load(Ordering::SeqCst), 2, "one retry, not more");
    }

    /// A 5xx is retried like any other transient failure, and the ladder
    /// stops at `FETCH_ATTEMPTS` rather than hammering the endpoint.
    #[tokio::test]
    async fn a_server_error_exhausts_the_attempts() {
        let (addr, hits) =
            spawn_scripted_server(|_| Some(http_response("503 Service Unavailable", ""))).await;

        let error = fetch_from(
            &reqwest::Client::new(),
            &format!("http://{addr}/"),
            TEST_BACKOFF,
        )
        .await
        .expect_err("a permanently unavailable endpoint must fail the fetch");

        assert_eq!(
            error.status().map(|status| status.as_u16()),
            Some(503),
            "the status is the diagnosis, not a parse error: {error}"
        );
        assert_eq!(hits.load(Ordering::SeqCst), FETCH_ATTEMPTS as usize);
    }

    /// A document that arrived intact and isn't the one we understand is an
    /// answer: re-downloading megabytes to re-parse them identically would
    /// only delay it.
    #[tokio::test]
    async fn a_malformed_document_is_not_retried() {
        let (addr, hits) =
            spawn_scripted_server(|_| Some(http_response("200 OK", "<html>nope</html>"))).await;

        let error = fetch_from(
            &reqwest::Client::new(),
            &format!("http://{addr}/"),
            TEST_BACKOFF,
        )
        .await
        .expect_err("a non-JSON body must fail the fetch");

        assert!(error.is_decode(), "expected a decode failure, got {error}");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "a verdict is not retried");
    }
}
