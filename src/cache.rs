//! Lazily-loading storage for `UUIDText` and DSC (shared-cache strings) data.
//!
//! [`StringStorage`] owns raw file bytes with stable addresses and loads them
//! on demand through a [`FileProvider`]; [`StringCatalog`] memoizes the parsed
//! zero-copy views ([`RawUUIDText`]/[`RawSharedCacheStrings`]) over that
//! storage. Together they let the parser resolve only the string files that
//! log entries actually reference, instead of reading every support file into
//! memory up front. Call [`StringStorage::preload`] to restore the eager
//! behavior (maximum throughput at maximum memory).
//!
//! Loaded data is never evicted: log entries borrow `&str` slices from the
//! stored buffers (zero-copy), so the memory ceiling is exactly the eager
//! footprint, reached only if every file ends up referenced.

use std::cell::RefCell;
use std::collections::HashSet;

use elsa::FrozenMap;
use log::warn;
use uuid::Uuid;

use crate::dsc::RawSharedCacheStrings;
use crate::traits::FileProvider;
use crate::uuidtext::RawUUIDText;

/// Owns raw `UUIDText`/DSC bytes with stable addresses; loads lazily via the provider.
///
/// The append-only maps hand out `&[u8]` borrows that stay valid while new
/// entries are inserted, which is what allows loading mid-parse while zero-copy
/// log entries keep borrowing from earlier buffers.
pub struct StringStorage<P: FileProvider> {
    provider: P,
    dsc: FrozenMap<Uuid, Box<[u8]>>,
    uuidtext: FrozenMap<Uuid, Box<[u8]>>,
}

impl<P: FileProvider> StringStorage<P> {
    /// Create an empty storage reading through `provider`.
    ///
    /// `provider` is taken by value; pass a reference (`&provider`) to keep
    /// ownership — `FileProvider` is implemented for `&T`.
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            dsc: FrozenMap::new(),
            uuidtext: FrozenMap::new(),
        }
    }

    /// Eagerly load every enumerable `UUIDText`/DSC file.
    ///
    /// Restores the parse-everything-up-front behavior: maximum throughput,
    /// maximum memory. Files that fail to load are skipped with a warning.
    pub fn preload(&self) {
        for uuid in self.provider.dsc_uuids().collect::<Vec<_>>() {
            self.dsc_bytes(&uuid);
        }
        for uuid in self.provider.uuidtext_uuids().collect::<Vec<_>>() {
            self.uuidtext_bytes(&uuid);
        }
    }

    /// Get-or-load the raw DSC bytes for `uuid`. `None` if the provider cannot supply them.
    pub(crate) fn dsc_bytes(&self, uuid: &Uuid) -> Option<&[u8]> {
        if let Some(bytes) = self.dsc.get(uuid) {
            return Some(bytes);
        }
        match self.provider.read_dsc(uuid) {
            Ok(bytes) => Some(self.dsc.insert(*uuid, bytes.into_boxed_slice())),
            Err(e) => {
                warn!("Failed to read DSC {uuid}: {e}");
                None
            }
        }
    }

    /// Get-or-load the raw `UUIDText` bytes for `uuid`. `None` if the provider cannot supply them.
    pub(crate) fn uuidtext_bytes(&self, uuid: &Uuid) -> Option<&[u8]> {
        if let Some(bytes) = self.uuidtext.get(uuid) {
            return Some(bytes);
        }
        match self.provider.read_uuidtext(uuid) {
            Ok(bytes) => Some(self.uuidtext.insert(*uuid, bytes.into_boxed_slice())),
            Err(e) => {
                warn!("Failed to read UUIDText {uuid}: {e}");
                None
            }
        }
    }
}

/// Memoized parsed views over a [`StringStorage`].
///
/// [`Self::get_dsc`]/[`Self::get_uuidtext`] parse on first access and cache
/// both successes and failures (a missing or unparsable file is only attempted
/// — and warned about — once). All strings extracted from the returned views
/// live as long as the storage borrow `'a`, not the catalog borrow.
pub struct StringCatalog<'a, P: FileProvider> {
    storage: &'a StringStorage<P>,
    dsc: FrozenMap<Uuid, Box<RawSharedCacheStrings<'a>>>,
    uuidtext: FrozenMap<Uuid, Box<RawUUIDText<'a>>>,
    dsc_missing: RefCell<HashSet<Uuid>>,
    uuidtext_missing: RefCell<HashSet<Uuid>>,
}

impl<'a, P: FileProvider> StringCatalog<'a, P> {
    /// Create an empty catalog over `storage`.
    pub fn new(storage: &'a StringStorage<P>) -> Self {
        Self {
            storage,
            dsc: FrozenMap::new(),
            uuidtext: FrozenMap::new(),
            dsc_missing: RefCell::new(HashSet::new()),
            uuidtext_missing: RefCell::new(HashSet::new()),
        }
    }

    /// Get-or-load the parsed DSC data for `uuid`.
    ///
    /// `None` for the nil UUID, unavailable files, and parse failures.
    pub fn get_dsc(&self, uuid: &Uuid) -> Option<&RawSharedCacheStrings<'a>> {
        if uuid.is_nil() {
            return None;
        }
        if let Some(parsed) = self.dsc.get(uuid) {
            return Some(parsed);
        }
        if self.dsc_missing.borrow().contains(uuid) {
            return None;
        }
        let Some(bytes) = self.storage.dsc_bytes(uuid) else {
            self.dsc_missing.borrow_mut().insert(*uuid);
            return None;
        };
        match RawSharedCacheStrings::parse(bytes) {
            Ok((_, parsed)) => Some(self.dsc.insert(*uuid, Box::new(parsed))),
            Err(e) => {
                warn!("Failed to parse DSC {uuid}: {e}");
                self.dsc_missing.borrow_mut().insert(*uuid);
                None
            }
        }
    }

    /// Get-or-load the parsed `UUIDText` data for `uuid`.
    ///
    /// `None` for the nil UUID, unavailable files, and parse failures.
    pub fn get_uuidtext(&self, uuid: &Uuid) -> Option<&RawUUIDText<'a>> {
        if uuid.is_nil() {
            return None;
        }
        if let Some(parsed) = self.uuidtext.get(uuid) {
            return Some(parsed);
        }
        if self.uuidtext_missing.borrow().contains(uuid) {
            return None;
        }
        let Some(bytes) = self.storage.uuidtext_bytes(uuid) else {
            self.uuidtext_missing.borrow_mut().insert(*uuid);
            return None;
        };
        match RawUUIDText::parse(bytes) {
            Ok((_, parsed)) => Some(self.uuidtext.insert(*uuid, Box::new(parsed))),
            Err(e) => {
                warn!("Failed to parse UUIDText {uuid}: {e}");
                self.uuidtext_missing.borrow_mut().insert(*uuid);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::{InMemoryProvider, LogarchiveProvider};
    use crate::helpers::tests::test_data_path;
    use std::cell::Cell;

    #[test]
    fn preload_loads_all_support_files() {
        let base = test_data_path().join("system_logs_tahoe.logarchive");
        let provider = LogarchiveProvider::new(&base);
        let storage = StringStorage::new(&provider);
        storage.preload();

        let catalog = StringCatalog::new(&storage);
        for uuid in provider.uuidtext_uuids() {
            assert!(catalog.get_uuidtext(&uuid).is_some(), "missing {uuid}");
        }
        for uuid in provider.dsc_uuids() {
            assert!(catalog.get_dsc(&uuid).is_some(), "missing {uuid}");
        }
        assert_eq!(provider.uuidtext_uuids().count(), 876);
        assert_eq!(provider.dsc_uuids().count(), 1);
    }

    #[test]
    fn lazy_get_matches_preloaded_get() {
        let base = test_data_path().join("system_logs_tahoe.logarchive");
        let provider = LogarchiveProvider::new(&base);
        let uuid = provider.uuidtext_uuids().next().unwrap();

        let eager_storage = StringStorage::new(&provider);
        eager_storage.preload();
        let eager = StringCatalog::new(&eager_storage);

        let lazy_storage = StringStorage::new(&provider);
        let lazy = StringCatalog::new(&lazy_storage);

        let eager_text = eager.get_uuidtext(&uuid).unwrap();
        let lazy_text = lazy.get_uuidtext(&uuid).unwrap();
        assert_eq!(eager_text.image_path(), lazy_text.image_path());
        assert_eq!(eager_text.entries.len(), lazy_text.entries.len());
    }

    /// Counts provider reads to prove misses are cached (attempted only once).
    struct CountingProvider {
        inner: InMemoryProvider,
        reads: Cell<usize>,
    }

    impl crate::traits::FileProvider for CountingProvider {
        fn tracev3_files(&self) -> impl Iterator<Item = impl crate::traits::SourceFile> {
            self.inner.tracev3_files()
        }
        fn timesync_files(&self) -> impl Iterator<Item = impl crate::traits::SourceFile> {
            self.inner.timesync_files()
        }
        fn read_uuidtext(&self, uuid: &Uuid) -> Result<Vec<u8>, std::io::Error> {
            self.reads.set(self.reads.get() + 1);
            self.inner.read_uuidtext(uuid)
        }
        fn read_dsc(&self, uuid: &Uuid) -> Result<Vec<u8>, std::io::Error> {
            self.reads.set(self.reads.get() + 1);
            self.inner.read_dsc(uuid)
        }
        fn uuidtext_uuids(&self) -> impl Iterator<Item = Uuid> {
            self.inner.uuidtext_uuids()
        }
        fn dsc_uuids(&self) -> impl Iterator<Item = Uuid> {
            self.inner.dsc_uuids()
        }
    }

    #[test]
    fn misses_and_hits_read_the_provider_once() {
        let provider = CountingProvider {
            inner: InMemoryProvider::default(),
            reads: Cell::new(0),
        };
        let storage = StringStorage::new(&provider);
        let catalog = StringCatalog::new(&storage);

        let uuid = Uuid::from_u128(1);
        assert!(catalog.get_uuidtext(&uuid).is_none());
        assert!(catalog.get_uuidtext(&uuid).is_none());
        assert_eq!(provider.reads.get(), 1, "miss should be cached");

        // Nil UUID short-circuits without touching the provider
        assert!(catalog.get_dsc(&Uuid::nil()).is_none());
        assert_eq!(provider.reads.get(), 1);
    }
}
