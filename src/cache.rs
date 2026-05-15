use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::dsc::SharedCacheStrings;
use crate::traits::FileProvider;
use crate::uuidtext::UUIDText;

const UUIDTEXT_CACHE_MAX: usize = 30;
const UUIDTEXT_EVICT_COUNT: usize = 5;
const DSC_CACHE_MAX: usize = 2;

/// A thread-safe cache for [`UUIDText`] and [`SharedCacheStrings`] data shared during log parsing.
///
/// Internally uses `Arc<RwLock<...>>` so that cloning produces a second handle to the same
/// underlying maps; concurrent reads proceed without blocking each other, while a load that
/// misses the cache takes an exclusive write lock only for the duration of the insert.
///
/// # Multithreaded tracev3 processing
/// ```rust,ignore
/// use macos_unifiedlogs::cache::StringCache;
/// use macos_unifiedlogs::filesystem::LogarchiveProvider;
/// use macos_unifiedlogs::parser::{build_log, collect_timesync};
/// use std::{path::PathBuf, sync::Arc};
///
/// let provider = Arc::new(LogarchiveProvider::new(&path));
/// let cache    = StringCache::default();
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
#[derive(Clone, Debug, Default)]
pub struct StringCache {
    uuidtext: Arc<RwLock<HashMap<String, Arc<UUIDText>>>>,
    dsc: Arc<RwLock<HashMap<String, Arc<SharedCacheStrings>>>>,
}

impl StringCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the cached [`UUIDText`] for `uuid`, loading it via `provider` if absent.
    ///
    /// `uuid2` is preserved from eviction alongside `uuid` so that a pair of UUIDs
    /// referenced by the same log entry are not simultaneously evicted.
    pub fn get_or_load_uuidtext(
        &self,
        uuid: &str,
        uuid2: &str,
        provider: &dyn FileProvider,
    ) -> Option<Arc<UUIDText>> {
        {
            let map = self.uuidtext.read().unwrap();
            if let Some(v) = map.get(uuid) {
                return Some(Arc::clone(v));
            }
        }

        let value = Arc::new(provider.read_uuidtext(uuid).ok()?);
        let mut map = self.uuidtext.write().unwrap();

        if map.len() >= UUIDTEXT_CACHE_MAX {
            let to_evict: Vec<String> = map
                .keys()
                .filter(|k| k.as_str() != uuid && k.as_str() != uuid2)
                .take(UUIDTEXT_EVICT_COUNT)
                .cloned()
                .collect();
            for key in to_evict {
                map.remove(&key);
            }
        }

        map.insert(uuid.to_string(), Arc::clone(&value));
        Some(value)
    }

    /// Returns the cached [`SharedCacheStrings`] for `uuid`, loading it via `provider` if absent.
    ///
    /// DSC files are large (~30 MB–150 MB each); at most [`DSC_CACHE_MAX`] are kept.
    /// `uuid2` is preserved from eviction alongside `uuid`.
    pub fn get_or_load_dsc(
        &self,
        uuid: &str,
        uuid2: &str,
        provider: &dyn FileProvider,
    ) -> Option<Arc<SharedCacheStrings>> {
        {
            let map = self.dsc.read().unwrap();
            if let Some(v) = map.get(uuid) {
                return Some(Arc::clone(v));
            }
        }

        let value = Arc::new(provider.read_dsc_uuid(uuid).ok()?);
        let mut map = self.dsc.write().unwrap();

        while map.len() >= DSC_CACHE_MAX {
            let key = map
                .keys()
                .find(|k| k.as_str() != uuid && k.as_str() != uuid2)
                .cloned();
            match key {
                Some(k) => {
                    map.remove(&k);
                }
                None => break,
            }
        }

        map.insert(uuid.to_string(), Arc::clone(&value));
        Some(value)
    }
}
