use std::sync::{Arc, RwLock};

use cached::{Cached, SizedCache};

use crate::dsc::SharedCacheStrings;
use crate::traits::{FileProvider, StringCache};
use crate::uuidtext::UUIDText;

/// A thread-safe cache for [`UUIDText`] and [`SharedCacheStrings`] data shared during log parsing.
///
/// Internally uses `Arc<RwLock<...>>` so that cloning produces a second handle to the same
/// underlying maps; concurrent reads proceed without blocking each other, while a load that
/// misses the cache takes an exclusive write lock only for the duration of the insert.
///
/// # Multithreaded tracev3 processing
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
    U: Cached<String, Arc<UUIDText>>,
    D: Cached<String, Arc<SharedCacheStrings>>,
> {
    uuidtext: Arc<RwLock<U>>,
    dsc: Arc<RwLock<D>>,
}

impl Default
    for MemoryStringCache<
        SizedCache<String, Arc<UUIDText>>,
        SizedCache<String, Arc<SharedCacheStrings>>,
    >
{
    fn default() -> Self {
        Self::with_size(100, 100)
    }
}

impl
    MemoryStringCache<
        SizedCache<String, Arc<UUIDText>>,
        SizedCache<String, Arc<SharedCacheStrings>>,
    >
{
    fn with_size(uuid_size: usize, shared_size: usize) -> Self {
        Self {
            uuidtext: Arc::new(RwLock::new(SizedCache::with_size(uuid_size))),
            dsc: Arc::new(RwLock::new(SizedCache::with_size(shared_size))),
        }
    }
}

impl<U, D> StringCache for MemoryStringCache<U, D>
where
    U: Cached<String, Arc<UUIDText>> + Send + Sync,
    D: Cached<String, Arc<SharedCacheStrings>> + Send + Sync,
{
    /// Returns the cached [`UUIDText`] for `uuid`, loading it via `provider` if absent.
    fn get_or_load_uuidtext(
        &self,
        uuid: &str,
        provider: &impl FileProvider,
    ) -> Option<Arc<UUIDText>> {
        {
            let mut map = self.uuidtext.write().unwrap();
            if let Some(v) = map.cache_get(uuid) {
                return Some(Arc::clone(v));
            }
        }

        let value = Arc::new(provider.read_uuidtext(uuid).ok()?);
        let mut map = self.uuidtext.write().unwrap();

        map.cache_set(uuid.to_string(), Arc::clone(&value));
        Some(value)
    }

    /// Returns the cached [`SharedCacheStrings`] for `uuid`, loading it via `provider` if absent.
    ///
    /// DSC files are large (~30 MB–150 MB each); at most [`DSC_CACHE_MAX`] are kept.
    /// `uuid2` is preserved from eviction alongside `uuid`.
    fn get_or_load_dsc(
        &self,
        uuid: &str,
        provider: &impl FileProvider,
    ) -> Option<Arc<SharedCacheStrings>> {
        {
            let mut map = self.dsc.write().unwrap();
            if let Some(v) = map.cache_get(uuid) {
                return Some(Arc::clone(v));
            }
        }

        let value = Arc::new(provider.read_dsc_uuid(uuid).ok()?);
        let mut map = self.dsc.write().unwrap();

        map.cache_set(uuid.to_string(), Arc::clone(&value));
        Some(value)
    }
}
