//! Name resolution for the mirror survey.
//!
//! Three concerns live here that the rest of the crate gets to treat as one:
//!
//! * a `Backend` choice — an async resolver where the platform lets us have
//!   one, the system resolver where it does not;
//! * a cache that doubles as the hand-off between the survey's resolve stage
//!   and its ping stage. Warming a name and resolving it on reqwest's behalf
//!   are the same operation, so the survey never threads addresses through its
//!   pipeline: it warms a name, and the ping that follows hits the cache.
//! * a reading of what a *failed* lookup meant — see `Cause`. A name the
//!   resolver answered about negatively is dropped; a resolver that declined
//!   to answer is simply asked again.
//!
//! The cache also collapses the mirror list's duplication for free. The list
//! carries ~805 usable entries but only ~487 distinct hosts, because `http://X`
//! and `https://X` are separate mirrors sharing one name.

use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use display_error_chain::DisplayErrorChain;
use rand::RngExt;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// What [`reqwest::dns::Resolving`] resolves to on the error path.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// How long a single lookup *attempt* may take before we give up on it.
///
/// Measured against the real mirror list: the slowest *legitimate* name is
/// `archlinux.nautile.nc` (New Caledonia) at 2.84s, so a tighter cap would
/// silently drop real mirrors. What this guards against is the other tail —
/// `ftp.linux.cz` and two others take ~102s to fail — so 5s is twenty times
/// better while keeping the far-but-valid names.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// How many times one name may be looked up before it is dropped.
///
/// Only failures that [`Cause::retryable`] accepts consume an attempt beyond
/// the first, so a name that genuinely does not exist still costs exactly one
/// lookup.
const LOOKUP_ATTEMPTS: usize = 3;

/// Base delay before a retry; doubled per attempt and jittered by ±50%.
///
/// The jitter is not decoration. The failure this retry exists for is a
/// resolver collapsing under a *burst*, and the burst is [`ASYNC_CONCURRENCY`]
/// lookups wide — so retrying in lockstep would re-send the same burst that
/// just failed, one backoff later. Spreading the retries is what makes them
/// land on a resolver that has caught up.
const RETRY_BACKOFF: Duration = Duration::from_millis(200);

/// Share of a stage's lookups that must be lost to the resolver itself before
/// the run says so out loud. See [`FailureReport::warn_if_resolver_bound`].
const LOSS_WARN_FRACTION: f64 = 0.1;

/// In-flight lookups allowed when the backend is asynchronous.
#[cfg(not(target_os = "android"))]
const ASYNC_CONCURRENCY: usize = 64;

/// In-flight lookups allowed when the backend is `getaddrinfo`.
///
/// Deliberately lower than [`ASYNC_CONCURRENCY`]: each of these occupies a
/// real thread on Tokio's blocking pool that nothing can cancel, so a name
/// that hangs holds its thread until the process exits — not until
/// [`LOOKUP_TIMEOUT`] says we stopped caring.
const SYSTEM_CONCURRENCY: usize = 32;

/// What a failed lookup says about the *name*, and therefore whether asking
/// again could change the answer.
///
/// The distinction is load-bearing. `NXDOMAIN` is an answer: the name does not
/// exist, and no amount of asking will conjure it. `REFUSED` is the resolver
/// declining to look, which says nothing whatsoever about the name. Collapsing
/// the two costs real mirrors — a DNS server that buckles under
/// [`SurveyResolver::lookup_concurrency`] lookups in flight (a home router's
/// built-in resolver is the usual culprit) answers the burst with `REFUSED`,
/// and every mirror behind those names silently leaves the run looking dead.
///
/// Ordering is the order [`FailureReport`] lists causes in: resolver's fault
/// first, since that is the half a reader can act on.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Cause {
    /// `REFUSED` — the resolver would not even try.
    Refused,
    /// `SERVFAIL` and the rest of the server-side response codes.
    ServerFailure,
    /// Nothing came back within [`LOOKUP_TIMEOUT`].
    TimedOut,
    /// A failure we cannot attribute to either side.
    Unclassified,
    /// `NXDOMAIN`, or an answer carrying no records for the name.
    NoSuchName,
    /// The resolver answered, but with an empty address set.
    NoAddresses,
}

impl Cause {
    /// Whether asking again could plausibly produce a different answer.
    fn retryable(self) -> bool {
        match self {
            Self::Refused | Self::ServerFailure | Self::TimedOut | Self::Unclassified => true,
            Self::NoSuchName | Self::NoAddresses => false,
        }
    }

    /// Whether the *resolver*, rather than the name, is what lost this lookup.
    ///
    /// [`Self::Unclassified`] deliberately answers `false`. It is what the
    /// system backend reports for everything — `getaddrinfo` hands back a bare
    /// `io::Error` with no response code in it — so counting it as the
    /// resolver's fault would let a run full of genuinely dead names
    /// masquerade as a broken DNS setup.
    fn blames_resolver(self) -> bool {
        match self {
            Self::Refused | Self::ServerFailure | Self::TimedOut => true,
            Self::Unclassified | Self::NoSuchName | Self::NoAddresses => false,
        }
    }

    /// Reads as a tally entry directly after a count: "132 refused".
    fn label(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::ServerFailure => "server failure",
            Self::TimedOut => "timed out",
            Self::Unclassified => "unclassified",
            Self::NoSuchName => "no such name",
            Self::NoAddresses => "no addresses",
        }
    }
}

/// A lookup that produced no addresses, and the reading of why.
struct Failure {
    cause: Cause,
    source: BoxError,
}

/// Reads a hickory failure for what it says about the name.
#[cfg(not(target_os = "android"))]
fn classify(error: &hickory_resolver::net::NetError) -> Cause {
    use hickory_resolver::{
        net::{DnsError, NetError},
        proto::op::ResponseCode,
    };
    match error {
        NetError::Dns(DnsError::ResponseCode(ResponseCode::Refused)) => Cause::Refused,
        // Every other response code reaching this arm is the server saying it
        // will not serve the query (`SERVFAIL`, `NOTIMP`, the BAD* family).
        // `NXDOMAIN` is not among them: hickory turns a negative answer into
        // `NoRecordsFound` before it gets here.
        NetError::Dns(DnsError::ResponseCode(_)) => Cause::ServerFailure,
        NetError::Dns(DnsError::NoRecordsFound(_)) => Cause::NoSuchName,
        NetError::Timeout => Cause::TimedOut,
        // Both enums are `#[non_exhaustive]`, and the rest of the variants are
        // transport and protocol errors that say nothing about the name.
        _ => Cause::Unclassified,
    }
}

enum Backend {
    #[cfg(not(target_os = "android"))]
    /// `hickory`, talking to whatever `/etc/resolv.conf` names. Lookups are
    /// ordinary futures, so [`LOOKUP_TIMEOUT`] genuinely cancels the work.
    ///
    /// Boxed only to keep the two variants a comparable size; there is exactly
    /// one of these per process.
    Async(Box<hickory_resolver::TokioResolver>),
    /// `getaddrinfo` on Tokio's blocking pool. Correct everywhere — notably on
    /// Android, where there is no `/etc/resolv.conf` for hickory to read and
    /// bionic is the only thing that knows the per-network DNS config — but
    /// the lookups cannot be cancelled once started.
    System,
}

impl Backend {
    /// Picks the best backend this platform and configuration can support.
    ///
    /// Never fails. An environment we cannot build an async resolver for
    /// degrades to the system resolver instead of taking the run down.
    fn detect() -> Self {
        #[cfg(target_os = "android")]
        {
            tracing::debug!("Android: resolving through the system resolver.");
            Self::System
        }

        #[cfg(not(target_os = "android"))]
        match hickory_resolver::TokioResolver::builder_tokio().and_then(|b| b.build()) {
            Ok(resolver) => Self::Async(Box::new(resolver)),
            Err(e) => {
                tracing::warn!(
                    "Could not build an async resolver ({}); falling back to the system \
                     resolver. Lookups will not be cancellable.",
                    DisplayErrorChain::new(&e)
                );
                Self::System
            }
        }
    }
}

struct Inner {
    backend: Backend,
    /// Port is left at 0 throughout: reqwest substitutes the scheme's
    /// conventional port for us, so the host is the whole cache key.
    cache: Mutex<HashMap<String, Vec<SocketAddr>>>,
    /// Why [`SurveyResolver::warm`] gave up on names, since the last
    /// [`SurveyResolver::take_failures`].
    failures: Mutex<BTreeMap<Cause, usize>>,
}

/// A resolver that reqwest can be built with and the survey can warm.
///
/// Cheap to clone — every clone shares one cache and one backend.
#[derive(Clone)]
pub struct SurveyResolver {
    inner: Arc<Inner>,
}

impl SurveyResolver {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                backend: Backend::detect(),
                cache: Mutex::new(HashMap::new()),
                failures: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    /// How many lookups the caller may keep in flight.
    ///
    /// Belongs to the resolver rather than to the survey because the safe
    /// number is a property of the backend, not of the workload.
    pub fn lookup_concurrency(&self) -> usize {
        match self.inner.backend {
            #[cfg(not(target_os = "android"))]
            Backend::Async(_) => ASYNC_CONCURRENCY,
            Backend::System => SYSTEM_CONCURRENCY,
        }
    }

    /// Resolves `host` into the cache, reporting whether it is usable at all.
    ///
    /// A `false` here is how the survey drops a dead name for the price of a
    /// DNS lookup instead of a full ping budget — and why the reason behind it
    /// is tallied rather than merely logged: a stage that loses most of its
    /// mirrors to `REFUSED` is a broken resolver, not a list of dead names,
    /// and only the tally can tell the two apart. See [`Self::take_failures`].
    pub async fn warm(&self, host: &str) -> bool {
        match self.inner.addrs_for(host).await {
            Ok(_) => true,
            Err(failure) => {
                tracing::debug!(
                    "Can't resolve {host} ({}): {}",
                    failure.cause.label(),
                    DisplayErrorChain::new(&*failure.source)
                );
                *self
                    .inner
                    .failures
                    .lock()
                    .expect("Failure tally mutex poisoned")
                    .entry(failure.cause)
                    .or_default() += 1;
                false
            }
        }
    }

    /// Takes the failures tallied since the last call.
    ///
    /// Draining rather than peeking is what keeps a report scoped to one
    /// stage: the main pipeline's resolver goes on to serve reqwest for the
    /// rest of the run, and those lookups are a different question.
    pub fn take_failures(&self) -> FailureReport {
        let counts = std::mem::take(
            &mut *self
                .inner
                .failures
                .lock()
                .expect("Failure tally mutex poisoned"),
        );
        FailureReport {
            counts,
            concurrency: self.lookup_concurrency(),
        }
    }
}

// `Default` is required by clippy::new_without_default for `pub fn new`;
// it just delegates.
impl Default for SurveyResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// What one resolve stage lost, and to what.
///
/// Counts *lookups*, not distinct names: the main pipeline warms `http://X`
/// and `https://X` as two separate mirrors, so a host that fails contributes
/// twice — which is also how it counts twice in the stage's own total, leaving
/// the ratio honest.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FailureReport {
    counts: BTreeMap<Cause, usize>,
    /// Carried along only so the warning can name the number the user would
    /// have to get their resolver past.
    concurrency: usize,
}

impl FailureReport {
    /// Lookups lost to the resolver itself — refusals, server failures and
    /// timeouts — as opposed to names it answered about honestly.
    pub fn resolver_side(&self) -> usize {
        self.counts
            .iter()
            .filter(|(cause, _)| cause.blames_resolver())
            .map(|(_, count)| count)
            .sum()
    }

    /// Whether this stage lost enough mirrors to the resolver to be worth
    /// interrupting the user over.
    fn is_resolver_bound(&self, total: usize) -> bool {
        total > 0 && self.resolver_side() as f64 >= total as f64 * LOSS_WARN_FRACTION
    }

    /// Says out loud when the resolver, rather than the mirror list, is what
    /// shrank a stage.
    ///
    /// Worth a `warn!` because the symptom is otherwise actively misleading:
    /// the stage reports a small `kept N/M`, which reads as "most of these
    /// mirrors are dead" when the mirrors were never asked about. The reasons
    /// sit at `debug`, so without this line the user has no way to tell the
    /// two situations apart from a normal run.
    pub fn warn_if_resolver_bound(&self, total: usize) {
        if !self.is_resolver_bound(total) {
            return;
        }
        tracing::warn!(
            "The DNS resolver dropped {} of {total} lookups without answering ({self}), even \
             after {LOOKUP_ATTEMPTS} attempts each. Those mirrors are most likely fine — they \
             were lost to the resolver, not to their names. A resolver that cannot take {} \
             lookups in flight does exactly this, and a home router's built-in one is the \
             usual culprit: check what `resolvectl status` (or /etc/resolv.conf) points at.",
            self.resolver_side(),
            self.concurrency,
        );
    }
}

impl fmt::Display for FailureReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.counts.is_empty() {
            return f.write_str("no failures");
        }
        for (i, (cause, count)) in self.counts.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{count} {}", cause.label())?;
        }
        Ok(())
    }
}

impl Inner {
    async fn addrs_for(&self, host: &str) -> Result<Vec<SocketAddr>, Failure> {
        // Scoped so the guard is never alive across the await below.
        if let Some(hit) = self.cache.lock().expect("Cache mutex poisoned").get(host) {
            return Ok(hit.clone());
        }

        let started = Instant::now();
        let addrs = self.lookup_with_retries(host).await?;
        // Warming keeps DNS out of every ping sample, which makes this the
        // only place its latency is visible at all.
        tracing::debug!("Resolved {host} in {:.2?}", started.elapsed());

        self.cache
            .lock()
            .expect("Cache mutex poisoned")
            .insert(host.to_owned(), addrs.clone());
        Ok(addrs)
    }

    /// Looks `host` up, asking again while the failure is the resolver's
    /// rather than the name's.
    ///
    /// A negative answer returns immediately: the retries exist for a resolver
    /// that would not answer, and spending three attempts to confirm an
    /// `NXDOMAIN` would just make dead names slower to drop.
    async fn lookup_with_retries(&self, host: &str) -> Result<Vec<SocketAddr>, Failure> {
        let mut attempt = 1;
        loop {
            let failure = match tokio::time::timeout(LOOKUP_TIMEOUT, self.lookup(host)).await {
                Ok(Ok(addrs)) => return Ok(addrs),
                Ok(Err(failure)) => failure,
                Err(_) => Failure {
                    cause: Cause::TimedOut,
                    source: format!("No answer for {host} within {LOOKUP_TIMEOUT:?}").into(),
                },
            };
            if !failure.cause.retryable() || attempt == LOOKUP_ATTEMPTS {
                return Err(failure);
            }

            // Seeded per retry rather than per lookup: retries are the rare
            // path, and this way the common one pays nothing for them.
            let mut rng: rand::rngs::StdRng = rand::make_rng();
            let backoff =
                (RETRY_BACKOFF * (1 << (attempt - 1))).mul_f64(rng.random_range(0.5..1.5));
            tracing::debug!(
                "Retrying {host} in {backoff:.2?} after attempt {attempt}/{LOOKUP_ATTEMPTS} ({})",
                failure.cause.label()
            );
            tokio::time::sleep(backoff).await;
            attempt += 1;
        }
    }

    async fn lookup(&self, host: &str) -> Result<Vec<SocketAddr>, Failure> {
        let addrs: Vec<SocketAddr> = match &self.backend {
            #[cfg(not(target_os = "android"))]
            Backend::Async(resolver) => match resolver.lookup_ip(host).await {
                Ok(found) => found.iter().map(|ip| SocketAddr::new(ip, 0)).collect(),
                Err(e) => {
                    return Err(Failure {
                        cause: classify(&e),
                        source: Box::new(e),
                    });
                }
            },
            // `getaddrinfo` flattens every failure into one `io::Error` with
            // no response code left in it, so there is nothing here to read: a
            // refusal and a missing name are the same value. We retry on the
            // chance it was the former and decline to blame either side.
            Backend::System => match tokio::net::lookup_host((host, 0)).await {
                Ok(addrs) => addrs.collect(),
                Err(e) => {
                    return Err(Failure {
                        cause: Cause::Unclassified,
                        source: Box::new(e),
                    });
                }
            },
        };
        if addrs.is_empty() {
            return Err(Failure {
                cause: Cause::NoAddresses,
                source: format!("No addresses for {host}").into(),
            });
        }
        Ok(addrs)
    }
}

impl Resolve for SurveyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        // The returned future is `'static`, so it takes a handle rather than a
        // borrow. That is the only reason `Inner` is behind an `Arc`.
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            // The cause matters to `warm`, which tallies it; reqwest only
            // ever gets to print the error, so it takes the source alone.
            let addrs = inner
                .addrs_for(name.as_str())
                .await
                .map_err(|failure| failure.source)?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of the classification: a resolver that declines to
    /// answer must not be read as a verdict on the name.
    #[test]
    fn refusals_retry_and_negative_answers_do_not() {
        assert!(Cause::Refused.retryable());
        assert!(Cause::ServerFailure.retryable());
        assert!(Cause::TimedOut.retryable());
        assert!(!Cause::NoSuchName.retryable());
        assert!(!Cause::NoAddresses.retryable());
    }

    /// Only causes we can actually attribute may accuse the resolver — see
    /// [`Cause::blames_resolver`] on why `Unclassified` stays out of it.
    #[test]
    fn only_attributable_causes_blame_the_resolver() {
        let report = FailureReport {
            counts: BTreeMap::from([
                (Cause::Refused, 40),
                (Cause::TimedOut, 2),
                (Cause::Unclassified, 7),
                (Cause::NoSuchName, 3),
            ]),
            concurrency: 64,
        };
        assert_eq!(report.resolver_side(), 42);
        assert_eq!(
            report.to_string(),
            "40 refused, 2 timed out, 7 unclassified, 3 no such name"
        );
    }

    #[test]
    fn warns_only_past_the_loss_threshold() {
        let refused = |n| FailureReport {
            counts: BTreeMap::from([(Cause::Refused, n)]),
            concurrency: 64,
        };
        // 10% of 100 is the threshold itself, which counts as resolver-bound.
        assert!(refused(10).is_resolver_bound(100));
        assert!(!refused(9).is_resolver_bound(100));
        // Names the resolver answered about honestly never trip it, however
        // many there are.
        let dead_names = FailureReport {
            counts: BTreeMap::from([(Cause::NoSuchName, 100)]),
            concurrency: 64,
        };
        assert!(!dead_names.is_resolver_bound(100));
        // An empty stage must not divide by zero into a warning.
        assert!(!FailureReport::default().is_resolver_bound(0));
    }
}
