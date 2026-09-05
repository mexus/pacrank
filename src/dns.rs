//! Name resolution for the mirror survey.
//!
//! Two concerns live here that the rest of the crate gets to treat as one:
//!
//! * a [`Backend`] choice — an async resolver where the platform lets us have
//!   one, the system resolver where it does not;
//! * a cache that doubles as the hand-off between the survey's resolve stage
//!   and its ping stage. Warming a name and resolving it on reqwest's behalf
//!   are the same operation, so the survey never threads addresses through its
//!   pipeline: it warms a name, and the ping that follows hits the cache.
//!
//! The cache also collapses the mirror list's duplication for free. The list
//! carries ~805 usable entries but only ~487 distinct hosts, because `http://X`
//! and `https://X` are separate mirrors sharing one name.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use display_error_chain::DisplayErrorChain;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// What [`reqwest::dns::Resolving`] resolves to on the error path.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// How long a single name may take before we give up on it.
///
/// Measured against the real mirror list: the slowest *legitimate* name is
/// `archlinux.nautile.nc` (New Caledonia) at 2.84s, so a tighter cap would
/// silently drop real mirrors. What this guards against is the other tail —
/// `ftp.linux.cz` and two others take ~102s to fail — so 5s is twenty times
/// better while keeping the far-but-valid names.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// DNS lookup instead of a full ping budget.
    pub async fn warm(&self, host: &str) -> bool {
        match self.inner.addrs_for(host).await {
            Ok(_) => true,
            Err(e) => {
                tracing::debug!("Can't resolve {host}: {}", DisplayErrorChain::new(&*e));
                false
            }
        }
    }
}

impl Default for SurveyResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Inner {
    async fn addrs_for(&self, host: &str) -> Result<Vec<SocketAddr>, BoxError> {
        // Scoped so the guard is never alive across the await below.
        if let Some(hit) = self.cache.lock().expect("Cache mutex poisoned").get(host) {
            return Ok(hit.clone());
        }

        let started = Instant::now();
        let addrs = tokio::time::timeout(LOOKUP_TIMEOUT, self.lookup(host))
            .await
            .map_err(|_| format!("No answer for {host} within {LOOKUP_TIMEOUT:?}"))??;
        // Warming keeps DNS out of every ping sample, which makes this the
        // only place its latency is visible at all.
        tracing::debug!("Resolved {host} in {:.2?}", started.elapsed());

        self.cache
            .lock()
            .expect("Cache mutex poisoned")
            .insert(host.to_owned(), addrs.clone());
        Ok(addrs)
    }

    async fn lookup(&self, host: &str) -> Result<Vec<SocketAddr>, BoxError> {
        let addrs: Vec<SocketAddr> = match &self.backend {
            #[cfg(not(target_os = "android"))]
            Backend::Async(resolver) => resolver
                .lookup_ip(host)
                .await?
                .iter()
                .map(|ip| SocketAddr::new(ip, 0))
                .collect(),
            Backend::System => tokio::net::lookup_host((host, 0)).await?.collect(),
        };
        if addrs.is_empty() {
            return Err(format!("No addresses for {host}").into());
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
            let addrs = inner.addrs_for(name.as_str()).await?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}
