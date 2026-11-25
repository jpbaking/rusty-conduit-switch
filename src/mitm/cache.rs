//! In-memory TTL cache of MITM leaf certificates — the **only** cache in rusty-conduit-switch.
//!
//! * Keyed by the normalized host (lowercase hostname or IP literal).
//! * Each entry expires `ttl` after it was signed. Expiry is checked lazily on every read
//!   (`now >= expires_at` is a miss), so an expired certificate is never returned even
//!   between reaper ticks.
//! * Per-host single-flight: concurrent misses for the same host wait on one async mutex,
//!   so N simultaneous handshakes sign exactly one leaf. Signing runs on the blocking pool.
//! * A background reaper ([`CertCache::spawn_reaper`]) evicts expired entries every
//!   `clamp(ttl / 4, 5s, 60s)` until its `CancellationToken` is cancelled.
//! * An optional entry cap ([`CertCache::with_max_entries`]) is enforced on insert: expired
//!   entries are reaped first, then the oldest live entries are evicted. Inserts are
//!   serialized so the cap is strict; cache hits never take that lock.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use rustls::sign::CertifiedKey;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::signer::{normalize_host, CertSource, SignError};
use crate::logging::Logger;

/// Lower bound of the reaper interval.
pub const MIN_REAP_INTERVAL: Duration = Duration::from_secs(5);
/// Upper bound of the reaper interval.
pub const MAX_REAP_INTERVAL: Duration = Duration::from_secs(60);

/// `clamp(ttl / 4, 5s, 60s)`.
pub fn reap_interval(ttl: Duration) -> Duration {
    (ttl / 4).clamp(MIN_REAP_INTERVAL, MAX_REAP_INTERVAL)
}

struct CacheEntry {
    key: Arc<CertifiedKey>,
    expires_at: Instant,
    /// Insertion sequence, breaking ties between equal `expires_at` values.
    seq: u64,
}

/// TTL-bounded leaf certificate cache with single-flight signing.
pub struct CertCache {
    entries: DashMap<String, CacheEntry>,
    inflight: DashMap<String, Arc<tokio::sync::Mutex<()>>>,
    source: Arc<dyn CertSource>,
    ttl: Duration,
    /// `0` means unlimited.
    max_entries: usize,
    /// Serializes inserts and holds the next insertion sequence number.
    insert_lock: Mutex<u64>,
    logger: OnceLock<Logger>,
}

impl std::fmt::Debug for CertCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertCache")
            .field("ttl", &self.ttl)
            .field("max_entries", &self.max_entries)
            .field("len", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl CertCache {
    pub fn new(source: Arc<dyn CertSource>, ttl: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            inflight: DashMap::new(),
            source,
            ttl,
            max_entries: 0,
            insert_lock: Mutex::new(0),
            logger: OnceLock::new(),
        }
    }

    /// Cap the number of stored entries (`0` = unlimited).
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// The configured entry cap (`0` = unlimited).
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Set the logger used for `VERBOSE` eviction messages. Only the first call has effect.
    pub fn set_logger(&self, logger: Logger) {
        let _ = self.logger.set(logger);
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Number of stored entries (expired entries not yet reaped included).
    ///
    /// Synchronizes with `insert_lock` so a concurrent eviction-plus-insert across different
    /// `DashMap` shards cannot produce a torn count exceeding `max_entries`.
    pub fn len(&self) -> usize {
        let _guard = self.insert_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return the cached, unexpired leaf for `host`, or sign (once per host, however many
    /// callers race) and cache a new one.
    pub async fn get_or_create(&self, host: &str) -> Result<Arc<CertifiedKey>, SignError> {
        let host = normalize_host(host);
        if let Some(hit) = self.lookup(&host, Instant::now()) {
            return Ok(hit);
        }
        let lock = self
            .inflight
            .entry(host.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let result = {
            let _flight = lock.lock().await;
            // Another caller may have signed while we waited.
            match self.lookup(&host, Instant::now()) {
                Some(hit) => Ok(hit),
                None => self.sign_and_store(&host).await,
            }
        };
        // Release our handle, then drop the per-host lock once only the map still holds it.
        drop(lock);
        self.inflight
            .remove_if(&host, |_, l| Arc::strong_count(l) <= 1);
        result
    }

    async fn sign_and_store(&self, host: &str) -> Result<Arc<CertifiedKey>, SignError> {
        let source = Arc::clone(&self.source);
        let h = host.to_string();
        let key = tokio::task::spawn_blocking(move || source.sign(&h))
            .await
            .map_err(|e| SignError::Sign {
                host: host.to_string(),
                reason: format!("signing task failed: {e}"),
            })??;
        self.store_at(host, Arc::clone(&key), Instant::now());
        Ok(key)
    }

    /// Insert a leaf signed at `now`, making room first if the cache is at its cap.
    fn store_at(&self, host: &str, key: Arc<CertifiedKey>, now: Instant) {
        let mut seq = self.insert_lock.lock().unwrap_or_else(|e| e.into_inner());
        if self.max_entries > 0
            && !self.entries.contains_key(host)
            && self.entries.len() >= self.max_entries
        {
            let reaped = self.reap_at(now);
            let mut evicted = 0;
            while self.entries.len() >= self.max_entries && self.evict_oldest() {
                evicted += 1;
            }
            if let Some(logger) = self.logger.get() {
                logger.verbose(format!(
                    "MITM cert cache at cap {}: reaped {reaped} expired, evicted {evicted} oldest",
                    self.max_entries
                ));
            }
        }
        self.entries.insert(
            host.to_string(),
            CacheEntry {
                key,
                expires_at: now + self.ttl,
                seq: *seq,
            },
        );
        *seq = seq.wrapping_add(1);
    }

    /// Remove the entry with the earliest expiry; returns whether one was removed.
    fn evict_oldest(&self) -> bool {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|e| (e.expires_at, e.seq))
            .map(|e| e.key().clone());
        oldest.is_some_and(|host| self.entries.remove(&host).is_some())
    }

    /// Lazy-expiry read: an entry with `now >= expires_at` is removed and reported as a miss.
    fn lookup(&self, host: &str, now: Instant) -> Option<Arc<CertifiedKey>> {
        {
            let entry = self.entries.get(host)?;
            if now < entry.expires_at {
                return Some(Arc::clone(&entry.key));
            }
        }
        self.entries.remove_if(host, |_, e| now >= e.expires_at);
        None
    }

    /// Remove every entry expired at `now`; returns the number evicted.
    pub fn reap_at(&self, now: Instant) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, e| now < e.expires_at);
        before.saturating_sub(self.entries.len())
    }

    /// Spawn the background reaper ticking every [`reap_interval`]`(ttl)`.
    pub fn spawn_reaper(
        self: &Arc<Self>,
        shutdown: CancellationToken,
        logger: Logger,
    ) -> JoinHandle<()> {
        self.spawn_reaper_every(reap_interval(self.ttl), shutdown, logger)
    }

    /// Spawn the reaper with an explicit interval (tests use sub-second intervals).
    pub fn spawn_reaper_every(
        self: &Arc<Self>,
        interval: Duration,
        shutdown: CancellationToken,
        logger: Logger,
    ) -> JoinHandle<()> {
        let cache = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await; // first tick completes immediately
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    _ = ticker.tick() => {
                        let evicted = cache.reap_at(Instant::now());
                        logger.verbose(format!(
                            "MITM cert cache reaper: evicted {evicted}, {} remaining",
                            cache.len()
                        ));
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::LogLevel;
    use crate::mitm::ca::{test_support::test_ca, CaMaterial};
    use crate::mitm::crypto_provider;
    use crate::mitm::signer::LeafSigner;

    use std::sync::atomic::{AtomicUsize, Ordering};

    fn quiet_logger() -> Logger {
        Logger::with_writer(LogLevel::Quiet, Box::new(std::io::sink()))
    }

    /// Real signer wrapper counting calls (and optionally slowing them down).
    struct Counting {
        inner: LeafSigner,
        calls: AtomicUsize,
        delay: Duration,
    }

    impl CertSource for Counting {
        fn sign(&self, host: &str) -> Result<Arc<CertifiedKey>, SignError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.delay);
            self.inner.sign(host)
        }
    }

    fn counting(delay: Duration) -> Arc<Counting> {
        let ca = test_ca();
        let m = CaMaterial::from_pem(ca.cert_pem.as_bytes(), ca.key_pem.as_bytes(), None)
            .unwrap()
            .validate()
            .unwrap();
        Arc::new(Counting {
            inner: LeafSigner::new(&m, Duration::from_secs(3600), crypto_provider()).unwrap(),
            calls: AtomicUsize::new(0),
            delay,
        })
    }

    #[test]
    fn reap_interval_is_clamped() {
        assert_eq!(reap_interval(Duration::from_secs(10)), MIN_REAP_INTERVAL);
        assert_eq!(
            reap_interval(Duration::from_secs(120)),
            Duration::from_secs(30)
        );
        assert_eq!(reap_interval(Duration::from_secs(3600)), MAX_REAP_INTERVAL);
    }

    #[tokio::test]
    async fn caches_hits_per_normalized_host() {
        let src = counting(Duration::ZERO);
        let cache = CertCache::new(src.clone(), Duration::from_secs(60));
        let a = cache.get_or_create("Example.com").await.unwrap();
        let b = cache.get_or_create("example.com.").await.unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(src.calls.load(Ordering::SeqCst), 1);
        let c = cache.get_or_create("other.example").await.unwrap();
        assert!(!Arc::ptr_eq(&a, &c));
        assert_eq!(src.calls.load(Ordering::SeqCst), 2);
        assert_eq!(cache.len(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_misses_sign_once() {
        let src = counting(Duration::from_millis(100));
        let cache = Arc::new(CertCache::new(src.clone(), Duration::from_secs(60)));
        let tasks: Vec<_> = (0..50)
            .map(|_| {
                let cache = Arc::clone(&cache);
                tokio::spawn(async move { cache.get_or_create("example.com").await.unwrap() })
            })
            .collect();
        let mut keys = Vec::new();
        for t in tasks {
            keys.push(t.await.unwrap());
        }
        assert_eq!(src.calls.load(Ordering::SeqCst), 1);
        assert!(keys.iter().all(|k| Arc::ptr_eq(k, &keys[0])));
        assert!(
            cache.inflight.is_empty(),
            "single-flight locks are released"
        );
    }

    #[tokio::test]
    async fn expired_entries_are_never_returned() {
        let src = counting(Duration::ZERO);
        let cache = CertCache::new(src.clone(), Duration::from_millis(150));
        let a = cache.get_or_create("example.com").await.unwrap();
        assert!(cache.lookup("example.com", Instant::now()).is_some());
        // Exactly at / after expiry is a miss, even without the reaper.
        let expires = cache.entries.get("example.com").unwrap().expires_at;
        assert!(cache.lookup("example.com", expires).is_none());
        assert!(cache.is_empty(), "lazy expiry removes the stale entry");

        let b = cache.get_or_create("example.com").await.unwrap();
        assert!(!Arc::ptr_eq(&a, &b));
        tokio::time::sleep(Duration::from_millis(200)).await;
        let c = cache.get_or_create("example.com").await.unwrap();
        assert!(!Arc::ptr_eq(&b, &c));
        assert_eq!(src.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn background_reaper_evicts_and_stops_on_cancel() {
        let src = counting(Duration::ZERO);
        let cache = Arc::new(CertCache::new(src, Duration::from_millis(100)));
        cache.get_or_create("a.example").await.unwrap();
        cache.get_or_create("b.example").await.unwrap();
        assert_eq!(cache.len(), 2);

        let token = CancellationToken::new();
        let reaper =
            cache.spawn_reaper_every(Duration::from_millis(50), token.clone(), quiet_logger());
        let mut evicted = false;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if cache.is_empty() {
                evicted = true;
                break;
            }
        }
        assert!(evicted, "reaper must evict expired entries without reads");

        token.cancel();
        tokio::time::timeout(Duration::from_secs(2), reaper)
            .await
            .expect("reaper stops on cancellation")
            .unwrap();
    }

    #[tokio::test]
    async fn reap_at_only_removes_expired() {
        let src = counting(Duration::ZERO);
        let cache = CertCache::new(src, Duration::from_secs(60));
        cache.get_or_create("a.example").await.unwrap();
        assert_eq!(cache.reap_at(Instant::now()), 0);
        assert_eq!(cache.reap_at(Instant::now() + Duration::from_secs(61)), 1);
        assert!(cache.is_empty());
    }

    fn capped(max: usize) -> (Arc<Counting>, CertCache) {
        let src = counting(Duration::ZERO);
        let cache = CertCache::new(src.clone(), Duration::from_secs(60)).with_max_entries(max);
        (src, cache)
    }

    fn store(cache: &CertCache, src: &Counting, host: &str, at: Instant) {
        cache.store_at(host, src.inner.sign(host).unwrap(), at);
    }

    #[test]
    fn cap_reaps_expired_before_evicting_live_entries() {
        let (src, cache) = capped(2);
        let t0 = Instant::now();
        // At t0+61 only `old` has expired.
        store(&cache, &src, "old.example", t0);
        store(&cache, &src, "b.example", t0 + Duration::from_secs(30));
        store(&cache, &src, "c.example", t0 + Duration::from_secs(61));
        assert_eq!(cache.len(), 2);
        assert!(!cache.entries.contains_key("old.example"));
        assert!(cache.entries.contains_key("b.example"));
        assert!(cache.entries.contains_key("c.example"));
    }

    #[test]
    fn cap_reaps_all_expired_entries_without_evicting_live_ones() {
        let (src, cache) = capped(3);
        let t0 = Instant::now();
        store(&cache, &src, "x.example", t0);
        store(&cache, &src, "y.example", t0);
        store(&cache, &src, "live.example", t0 + Duration::from_secs(50));
        store(&cache, &src, "new.example", t0 + Duration::from_secs(61));
        assert_eq!(cache.len(), 2);
        assert!(cache.entries.contains_key("live.example"));
        assert!(cache.entries.contains_key("new.example"));
    }

    #[test]
    fn cap_evicts_oldest_live_entry_first() {
        let (src, cache) = capped(2);
        let t0 = Instant::now();
        store(&cache, &src, "a.example", t0);
        store(&cache, &src, "b.example", t0 + Duration::from_secs(1));
        store(&cache, &src, "c.example", t0 + Duration::from_secs(2));
        assert!(!cache.entries.contains_key("a.example"));
        assert!(cache.entries.contains_key("b.example"));
        store(&cache, &src, "d.example", t0 + Duration::from_secs(3));
        assert!(!cache.entries.contains_key("b.example"));
        assert!(cache.entries.contains_key("c.example"));
        assert!(cache.entries.contains_key("d.example"));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn cap_breaks_expiry_ties_by_insertion_order() {
        let (src, cache) = capped(2);
        let t0 = Instant::now();
        store(&cache, &src, "first.example", t0);
        store(&cache, &src, "second.example", t0);
        store(&cache, &src, "third.example", t0);
        assert!(!cache.entries.contains_key("first.example"));
        assert!(cache.entries.contains_key("second.example"));
    }

    #[test]
    fn replacing_a_key_at_cap_evicts_nothing() {
        let (src, cache) = capped(2);
        let t0 = Instant::now();
        store(&cache, &src, "a.example", t0);
        store(&cache, &src, "b.example", t0 + Duration::from_secs(1));
        store(&cache, &src, "a.example", t0 + Duration::from_secs(2));
        assert_eq!(cache.len(), 2);
        assert!(cache.entries.contains_key("b.example"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cap_is_strict_under_concurrent_inserts() {
        let (_src, cache) = capped(5);
        let cache = Arc::new(cache);
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watcher = {
            let (cache, done) = (Arc::clone(&cache), Arc::clone(&done));
            tokio::spawn(async move {
                let mut max_seen = 0;
                while !done.load(Ordering::SeqCst) {
                    max_seen = max_seen.max(cache.len());
                    tokio::task::yield_now().await;
                }
                max_seen
            })
        };
        let tasks: Vec<_> = (0..60)
            .map(|i| {
                let cache = Arc::clone(&cache);
                tokio::spawn(async move {
                    cache.get_or_create(&format!("h{i}.example")).await.unwrap();
                })
            })
            .collect();
        for t in tasks {
            t.await.unwrap();
        }
        done.store(true, Ordering::SeqCst);
        assert!(watcher.await.unwrap() <= 5);
        assert_eq!(cache.len(), 5);
    }

    #[tokio::test]
    async fn cap_zero_is_unlimited() {
        let (_src, cache) = capped(0);
        for i in 0..25 {
            cache.get_or_create(&format!("h{i}.example")).await.unwrap();
        }
        assert_eq!(cache.len(), 25);
    }
}
