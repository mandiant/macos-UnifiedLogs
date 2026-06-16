use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::{BuildHasher, Hash};
use std::sync::{Arc, RwLock};

use crate::dsc::SharedCacheStrings;
use crate::traits::{Cache, FileProvider, StringCache};
use crate::uuidtext::UUIDText;

/// A thread-safe cache for [`UUIDText`] and [`SharedCacheStrings`] data shared during log parsing.
///
/// The default implementation (`MemoryStringCache::default()`) uses unbounded `HashMap` maps
/// wrapped in `Arc<RwLock<...>>`. Cloning produces a second handle to the same underlying
/// maps — concurrent reads proceed without blocking each other, while a cache miss takes an
/// exclusive write lock only for the duration of the insert.
///
/// ## Bringing your own cache
///
/// The default implementation grows without bound. For long-running processes or large log
/// collections, use [`MemoryStringCache::new`] to supply eviction-aware backends by implementing
/// [`Cache`] for any type with interior mutability:
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use macos_unifiedlogs::{cache::MemoryStringCache, traits::Cache};
/// use macos_unifiedlogs::{dsc::SharedCacheStrings, uuidtext::UUIDText};
///
/// struct BoundedCache(/* e.g. moka::sync::Cache<String, Arc<T>> */);
///
/// impl Cache<String, Arc<UUIDText>> for BoundedCache { /* ... */ }
/// impl Cache<String, Arc<SharedCacheStrings>> for BoundedCache { /* ... */ }
///
/// let cache = MemoryStringCache::new(BoundedCache::new(), BoundedCache::new());
/// ```
///
/// ## Multithreaded tracev3 processing
/// ```rust,no_run
/// use crate::macos_unifiedlogs::traits::FileProvider;
/// use macos_unifiedlogs::cache::MemoryStringCache;
/// use macos_unifiedlogs::filesystem::LogarchiveProvider;
/// use macos_unifiedlogs::parser::{build_log, collect_timesync};
/// use std::{path::PathBuf, sync::Arc};
///
/// let provider = Arc::new(LogarchiveProvider::new(&PathBuf::from("/tmp/log.logarchive")));
/// let cache    = MemoryStringCache::default();
/// let timesync = collect_timesync(provider.as_ref()).unwrap();
///
/// std::thread::scope(|s| {
///     for file in provider.tracev3_files() {
///         let provider = Arc::clone(&provider);
///         let cache    = cache.clone();       // cheap Arc clone
///         let timesync = &timesync;
///         s.spawn(move || {
///             // parse + build_log with the shared cache
///         });
///     }
/// });
/// ```
#[derive(Clone, Debug)]
pub struct MemoryStringCache<
    U: Cache<String, Arc<UUIDText>> + Send + Sync,
    D: Cache<String, Arc<SharedCacheStrings>> + Send + Sync,
> {
    uuidtext: U,
    dsc: D,
}

impl<U, D> MemoryStringCache<U, D>
where
    U: Cache<String, Arc<UUIDText>> + Send + Sync,
    D: Cache<String, Arc<SharedCacheStrings>> + Send + Sync,
{
    pub fn new(uuidtext: U, dsc: D) -> Self {
        Self { uuidtext, dsc }
    }
}

impl Default
    for MemoryStringCache<
        Arc<RwLock<HashMap<String, Arc<UUIDText>>>>,
        Arc<RwLock<HashMap<String, Arc<SharedCacheStrings>>>>,
    >
{
    fn default() -> Self {
        Self {
            uuidtext: Arc::new(RwLock::new(HashMap::new())),
            dsc: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl<K, V, B> Cache<K, V> for RwLock<HashMap<K, V, B>>
where
    K: Eq + Hash,
    V: Clone,
    B: BuildHasher,
{
    fn get<Q>(&self, item: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.read().ok()?.get(item).cloned()
    }

    fn insert(&self, key: K, value: V) -> Option<V> {
        self.write().ok()?.insert(key, value)
    }
}

impl<K, V, B> Cache<K, V> for Arc<RwLock<HashMap<K, V, B>>>
where
    K: Eq + Hash,
    V: Clone,
    B: BuildHasher,
{
    fn get<Q>(&self, item: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.read().ok()?.get(item).cloned()
    }

    fn insert(&self, key: K, value: V) -> Option<V> {
        self.write().ok()?.insert(key, value)
    }
}

impl<U, D> StringCache for MemoryStringCache<U, D>
where
    U: Cache<String, Arc<UUIDText>> + Send + Sync,
    D: Cache<String, Arc<SharedCacheStrings>> + Send + Sync,
{
    /// Returns the cached [`UUIDText`] for `uuid`, loading it via `provider` if absent.
    fn get_or_load_uuidtext(
        &self,
        uuid: &str,
        provider: &impl FileProvider,
    ) -> Option<Arc<UUIDText>> {
        {
            if let Some(v) = self.uuidtext.get(uuid) {
                return Some(Arc::clone(&v));
            }
        }

        let value = Arc::new(provider.read_uuidtext(uuid).ok()?);
        self.uuidtext.insert(uuid.to_string(), Arc::clone(&value));
        Some(value)
    }

    /// Returns the cached [`SharedCacheStrings`] for `uuid`, loading it via `provider` if absent.
    ///
    /// DSC files are large (~30 MB–150 MB each). The default `HashMap`-backed implementation
    /// grows without bound; supply a bounded `D` via [`MemoryStringCache::new`] if eviction
    /// is required.
    fn get_or_load_dsc(
        &self,
        uuid: &str,
        provider: &impl FileProvider,
    ) -> Option<Arc<SharedCacheStrings>> {
        {
            if let Some(v) = self.dsc.get(uuid) {
                return Some(Arc::clone(&v));
            }
        }

        let value = Arc::new(provider.read_dsc_uuid(uuid).ok()?);

        self.dsc.insert(uuid.to_string(), Arc::clone(&value));
        Some(value)
    }
}
