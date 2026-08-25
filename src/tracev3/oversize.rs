//! Oversize payload cache with lazy cross-file resolution.
//!
//! Oversize chunks carry strings too large for regular firehose entries and
//! are looked up by `(boot_uuid, data_ref_index, first_proc_id, second_proc_id)`
//! when a firehose entry references them via `data_ref`. The proc ids and the
//! data ref are per-boot counters, so the boot UUID of the enclosing header
//! chunk is what keeps early-boot daemons of different boots apart. The payload is flushed to
//! disk out-of-band while the small referencing entry lingers in its process's
//! in-memory buffer, so the referenced chunk may live in a tracev3 file that
//! has not been visited yet. [`OversizeCache::with_provider`] resolves such
//! backward references by lazily harvesting oversize chunks from
//! not-yet-visited files on a miss.

use crate::chunk::ChunkSetReader;
use crate::chunks::oversize::RawOversize;
use crate::chunks::{ChunkTag, ChunksetPayload};
use crate::chunks_reader::RawChunksReader;
use crate::error::NomExt;
use crate::header::RawHeaderChunk;
use crate::traits::{FileProvider, SourceFile};
use elsa::FrozenMap;
use log::warn;
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::io::Read;
use uuid::Uuid;

/// Key identifying an oversize payload:
/// `(boot_uuid, data_ref_index, first_proc_id, second_proc_id)`.
type OversizeKey = (Uuid, u32, u64, u32);

/// Cache for oversize log entries, threaded across chunksets and tracev3 files.
///
/// A cache built with [`Self::with_provider`] resolves backward cross-file
/// references by harvesting oversize chunks from not-yet-visited files on a
/// miss, one file at a time, stopping as soon as the wanted key appears. Each
/// file is harvested at most once; once every file has been covered, misses
/// are definitive (the referenced log rolled) and cost no further I/O.
///
/// The append-only map hands out `&[u8]` borrows that stay valid while new
/// entries are inserted mid-visit (same pattern as
/// [`crate::cache::StringCatalog`]).
pub struct OversizeCache<'p> {
    entries: FrozenMap<OversizeKey, Box<[u8]>>,
    inserted_bytes: Cell<usize>,
    harvester: Box<dyn OversizeHarvester + 'p>,
}

impl OversizeCache<'_> {
    /// Cache without a harvest source: misses are final.
    pub fn new() -> Self {
        Self {
            entries: FrozenMap::new(),
            inserted_bytes: Cell::new(0),
            harvester: Box::new(NoHarvester),
        }
    }
}

impl Default for OversizeCache<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'p> OversizeCache<'p> {
    /// Cache that resolves misses by lazily harvesting oversize chunks from
    /// the provider's not-yet-visited tracev3 files.
    ///
    /// Visit loops must call [`Self::mark_covered`] with each file's
    /// `source_path()` before visiting it, so the harvester skips files whose
    /// oversize chunks the visit itself inserts. Files are identified by their
    /// `source_path()` string; providers yielding duplicate paths would
    /// collapse in that bookkeeping.
    pub fn with_provider(provider: &'p impl FileProvider) -> Self {
        Self {
            entries: FrozenMap::new(),
            inserted_bytes: Cell::new(0),
            harvester: Box::new(ProviderHarvester {
                provider,
                covered: RefCell::new(HashSet::new()),
                exhausted: Cell::new(false),
            }),
        }
    }

    /// Tell the harvester this file's oversize chunks are handled by the
    /// visit loop. No-op for a cache without a harvest source.
    pub fn mark_covered(&self, source_path: &str) {
        self.harvester.mark_covered(source_path);
    }

    pub(super) fn insert(&self, boot_uuid: Uuid, oversize: &RawOversize<'_>) {
        let key = (
            boot_uuid,
            oversize.data_ref_index,
            oversize.first_proc_id,
            oversize.second_proc_id,
        );
        // First writer wins; skip the Box allocation for duplicates.
        if self.entries.get(&key).is_some() {
            return;
        }
        self.inserted_bytes
            .set(self.inserted_bytes.get() + oversize.oversize_data.len());
        self.entries
            .insert(key, oversize.oversize_data.to_vec().into_boxed_slice());
    }

    fn get(
        &self,
        boot_uuid: Uuid,
        data_ref: u32,
        first_proc_id: u64,
        second_proc_id: u32,
    ) -> Option<&[u8]> {
        self.entries
            .get(&(boot_uuid, data_ref, first_proc_id, second_proc_id))
    }

    /// Get, harvesting one not-yet-covered file at a time on a miss until the
    /// key appears or every file has been covered.
    pub(super) fn get_or_harvest(
        &self,
        boot_uuid: Uuid,
        data_ref: u32,
        first_proc_id: u64,
        second_proc_id: u32,
    ) -> Option<&[u8]> {
        loop {
            if let Some(data) = self.get(boot_uuid, data_ref, first_proc_id, second_proc_id) {
                return Some(data);
            }
            if !self.harvester.harvest_next(self) {
                return None;
            }
        }
    }
}

/// Miss handler for [`OversizeCache`]: dyn-erases the provider type so the
/// cache doesn't grow a generic parameter.
trait OversizeHarvester {
    /// Harvest oversize chunks from ONE not-yet-covered file into `cache`.
    /// Returns `false` when every file has been covered (exhausted).
    fn harvest_next(&self, cache: &OversizeCache<'_>) -> bool;
    fn mark_covered(&self, source_path: &str);
}

/// Harvester for caches without a harvest source: misses are final.
struct NoHarvester;

impl OversizeHarvester for NoHarvester {
    fn harvest_next(&self, _cache: &OversizeCache<'_>) -> bool {
        false
    }
    fn mark_covered(&self, _source_path: &str) {}
}

struct ProviderHarvester<'p, P: FileProvider> {
    provider: &'p P,
    /// Files already visited or harvested, keyed by `source_path()`.
    covered: RefCell<HashSet<String>>,
    /// Sticky: once every file is covered, misses are definitive with zero I/O.
    exhausted: Cell<bool>,
}

impl<P: FileProvider> OversizeHarvester for ProviderHarvester<'_, P> {
    fn harvest_next(&self, cache: &OversizeCache<'_>) -> bool {
        if self.exhausted.get() {
            return false;
        }
        // Re-enumerating is the supported way to get a second pass over the
        // provider's files (individual SourceFiles are not re-readable).
        for mut source in self.provider.tracev3_files() {
            let path = source.source_path().to_string();
            if self.covered.borrow().contains(&path) {
                continue;
            }
            self.covered.borrow_mut().insert(path.clone());
            let mut data = Vec::new();
            if let Err(e) = source.reader().read_to_end(&mut data) {
                warn!("Failed to read {path} during oversize harvest: {e}");
                continue;
            }
            harvest_oversize(&data, cache);
            return true;
        }
        self.exhausted.set(true);
        false
    }

    fn mark_covered(&self, source_path: &str) {
        self.covered.borrow_mut().insert(source_path.to_string());
    }
}

/// Walk a tracev3 buffer extracting only Oversize chunks into `cache`.
///
/// Header/Catalog chunks are skipped without parsing; only chunksets are
/// decompressed (oversize chunks live inside them). Parse errors are logged
/// and skipped, mirroring `visit_tracev3`'s warn-and-continue behavior.
fn harvest_oversize(data: &[u8], cache: &OversizeCache<'_>) {
    // Boot of the chunks being read: a file holds one header chunk per boot,
    // each applying to the chunksets that follow it.
    let mut boot_uuid = Uuid::nil();
    for raw in RawChunksReader::new_top_level(data) {
        let raw = match raw {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to parse top chunk during oversize harvest: {e}");
                break;
            }
        };
        if raw.preamble.tag == ChunkTag::Header {
            match RawHeaderChunk::parse(raw.data) {
                Ok((_, header)) => boot_uuid = header.boot_uuid,
                Err(e) => warn!(
                    "Failed to parse header chunk during oversize harvest: {}",
                    e.to_parse_error()
                ),
            }
        }
        if raw.preamble.tag != ChunkTag::Chunkset {
            continue;
        }
        let payload = match ChunksetPayload::parse(raw.data) {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to parse chunkset during oversize harvest: {e}");
                continue;
            }
        };
        let mut reader = ChunkSetReader::new(payload);
        while let Some(inner) = reader.next() {
            let inner = match inner {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed to parse inner chunk during oversize harvest: {e}");
                    break;
                }
            };
            if inner.preamble.tag != ChunkTag::Oversize {
                continue;
            }
            match RawOversize::parse(inner.data) {
                Ok((_, ov)) => cache.insert(boot_uuid, &ov),
                Err(e) => {
                    warn!(
                        "Failed to parse oversize chunk during oversize harvest: {}",
                        e.to_parse_error()
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::RAW_HEADER_CHUNK_SIZE;
    use crate::helpers::tests::test_data_path;
    use std::collections::HashMap;
    use uuid::uuid;

    const BOOT_A: Uuid = uuid!("aaaaaaaa-0000-0000-0000-000000000001");
    const BOOT_B: Uuid = uuid!("bbbbbbbb-0000-0000-0000-000000000002");

    // --- OversizeCache tests ---

    #[test]
    fn test_oversize_cache_insert_and_get() {
        let cache = OversizeCache::new();
        cache
            .entries
            .insert((BOOT_A, 1, 100, 200), vec![1, 2, 3, 4].into_boxed_slice());
        assert_eq!(cache.get(BOOT_A, 1, 100, 200), Some(&[1, 2, 3, 4][..]));
    }

    #[test]
    fn test_oversize_cache_miss() {
        let cache = OversizeCache::new();
        assert_eq!(cache.get(BOOT_A, 1, 100, 200), None);
    }

    #[test]
    fn test_oversize_cache_different_key() {
        let cache = OversizeCache::new();
        cache
            .entries
            .insert((BOOT_A, 1, 100, 200), vec![1, 2, 3].into_boxed_slice());
        // Different boot
        assert_eq!(cache.get(BOOT_B, 1, 100, 200), None);
        // Different data_ref
        assert_eq!(cache.get(BOOT_A, 2, 100, 200), None);
        // Different first_proc_id
        assert_eq!(cache.get(BOOT_A, 1, 101, 200), None);
        // Different second_proc_id
        assert_eq!(cache.get(BOOT_A, 1, 100, 201), None);
    }

    #[test]
    fn test_get_or_harvest_without_harvester_is_plain_miss() {
        let cache = OversizeCache::new();
        assert_eq!(cache.get_or_harvest(BOOT_A, 1, 100, 200), None);
    }

    // --- oversize harvester tests ---

    #[test]
    fn test_harvest_oversize_extracts_only_oversize_chunks() {
        let data = std::fs::read(
            test_data_path().join("Bad Data/TraceV3/Bad_header_0000000000000005.tracev3"),
        )
        .unwrap();
        let cache = OversizeCache::new();
        harvest_oversize(&data, &cache);
        // Count established by chunk::tests::visit over the same file
        assert_eq!(cache.entries.len(), 28);
    }

    /// Append a header chunk announcing `boot_uuid` (all other fields zero).
    fn push_header_chunk(out: &mut Vec<u8>, boot_uuid: Uuid) {
        out.extend_from_slice(&(ChunkTag::Header as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // sub_tag
        out.extend_from_slice(&(RAW_HEADER_CHUNK_SIZE as u64).to_le_bytes());
        let mut body = [0u8; RAW_HEADER_CHUNK_SIZE];
        body[128..144].copy_from_slice(boot_uuid.as_bytes());
        out.extend_from_slice(&body);
    }

    /// Append one uncompressed (`bv4-`) chunkset containing a single oversize chunk.
    fn push_oversize_chunkset(
        out: &mut Vec<u8>,
        data_ref: u32,
        first_proc_id: u64,
        second_proc_id: u32,
        payload: &[u8],
    ) {
        let mut inner = Vec::new();
        inner.extend_from_slice(&(ChunkTag::Oversize as u32).to_le_bytes());
        inner.extend_from_slice(&0u32.to_le_bytes()); // sub_tag
        inner.extend_from_slice(&((32 + payload.len()) as u64).to_le_bytes());
        inner.extend_from_slice(&first_proc_id.to_le_bytes());
        inner.extend_from_slice(&second_proc_id.to_le_bytes());
        inner.push(0); // ttl
        inner.extend_from_slice(&[0; 3]); // reserved
        inner.extend_from_slice(&0u64.to_le_bytes()); // continuous_time
        inner.extend_from_slice(&data_ref.to_le_bytes());
        inner.extend_from_slice(&(payload.len() as u16).to_le_bytes()); // public size
        inner.extend_from_slice(&0u16.to_le_bytes()); // private size
        inner.extend_from_slice(payload);

        let mut chunkset = Vec::new();
        chunkset.extend_from_slice(b"bv4-");
        chunkset.extend_from_slice(&(inner.len() as u32).to_le_bytes());
        chunkset.extend_from_slice(&inner);

        out.extend_from_slice(&(ChunkTag::Chunkset as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // sub_tag
        out.extend_from_slice(&(chunkset.len() as u64).to_le_bytes());
        out.extend_from_slice(&chunkset);
        while !out.len().is_multiple_of(8) {
            out.push(0);
        }
    }

    /// Build a minimal tracev3 buffer: a `BOOT_A` header followed by one
    /// chunkset holding a single oversize chunk.
    fn synth_tracev3_with_oversize(
        data_ref: u32,
        first_proc_id: u64,
        second_proc_id: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        push_header_chunk(&mut out, BOOT_A);
        push_oversize_chunkset(&mut out, data_ref, first_proc_id, second_proc_id, payload);
        out
    }

    #[test]
    fn test_harvest_keys_oversize_by_boot() {
        // Same (data_ref, proc ids) under two boots in one file: both survive.
        let mut data = Vec::new();
        push_header_chunk(&mut data, BOOT_A);
        push_oversize_chunkset(&mut data, 1, 10, 20, b"FROM A");
        push_header_chunk(&mut data, BOOT_B);
        push_oversize_chunkset(&mut data, 1, 10, 20, b"FROM B");

        let cache = OversizeCache::new();
        harvest_oversize(&data, &cache);
        assert_eq!(cache.get(BOOT_A, 1, 10, 20), Some(&b"FROM A"[..]));
        assert_eq!(cache.get(BOOT_B, 1, 10, 20), Some(&b"FROM B"[..]));
        assert_eq!(cache.get(Uuid::nil(), 1, 10, 20), None);
    }

    #[test]
    fn test_get_or_harvest_across_files_of_different_boots() {
        // An older boot's file harvested first must not shadow the newer boot's payload.
        let mut newer = Vec::new();
        push_header_chunk(&mut newer, BOOT_B);
        push_oversize_chunkset(&mut newer, 1, 10, 20, b"NEWER");
        let provider = CountingProvider::new(vec![
            ("older", synth_tracev3_with_oversize(1, 10, 20, b"OLDER")),
            ("newer", newer),
        ]);
        let cache = OversizeCache::with_provider(&provider);

        assert_eq!(cache.get_or_harvest(BOOT_B, 1, 10, 20), Some(&b"NEWER"[..]));
        assert_eq!(cache.get_or_harvest(BOOT_A, 1, 10, 20), Some(&b"OLDER"[..]));
    }

    /// Provider counting per-file reads and `tracev3_files()` enumerations.
    struct CountingProvider {
        files: Vec<(String, Vec<u8>)>,
        reads: RefCell<HashMap<String, usize>>,
        enumerations: Cell<usize>,
    }

    impl CountingProvider {
        fn new(files: Vec<(&str, Vec<u8>)>) -> Self {
            Self {
                files: files
                    .into_iter()
                    .map(|(name, data)| (name.to_string(), data))
                    .collect(),
                reads: RefCell::new(HashMap::new()),
                enumerations: Cell::new(0),
            }
        }

        fn reads(&self, name: &str) -> usize {
            self.reads.borrow().get(name).copied().unwrap_or(0)
        }
    }

    struct CountingSource<'a> {
        name: &'a str,
        data: &'a [u8],
        reads: &'a RefCell<HashMap<String, usize>>,
    }

    impl SourceFile for CountingSource<'_> {
        fn reader(&mut self) -> impl Read {
            *self
                .reads
                .borrow_mut()
                .entry(self.name.to_string())
                .or_insert(0) += 1;
            self.data
        }
        fn source_path(&self) -> &str {
            self.name
        }
    }

    impl FileProvider for CountingProvider {
        fn tracev3_files(&self) -> impl Iterator<Item = impl SourceFile> {
            self.enumerations.set(self.enumerations.get() + 1);
            self.files.iter().map(|(name, data)| CountingSource {
                name,
                data,
                reads: &self.reads,
            })
        }
        fn timesync_files(&self) -> impl Iterator<Item = impl SourceFile> {
            self.files[..0].iter().map(|(name, data)| CountingSource {
                name,
                data,
                reads: &self.reads,
            })
        }
        fn read_uuidtext(&self, _uuid: &Uuid) -> Result<Vec<u8>, std::io::Error> {
            Err(std::io::ErrorKind::NotFound.into())
        }
        fn read_dsc(&self, _uuid: &Uuid) -> Result<Vec<u8>, std::io::Error> {
            Err(std::io::ErrorKind::NotFound.into())
        }
        fn uuidtext_uuids(&self) -> impl Iterator<Item = Uuid> {
            std::iter::empty()
        }
        fn dsc_uuids(&self) -> impl Iterator<Item = Uuid> {
            std::iter::empty()
        }
    }

    #[test]
    fn test_get_or_harvest_scans_one_file_at_a_time_and_resumes() {
        let provider = CountingProvider::new(vec![
            ("a", synth_tracev3_with_oversize(1, 10, 20, b"AAA")),
            ("b", synth_tracev3_with_oversize(2, 10, 20, b"BBB")),
            ("c", synth_tracev3_with_oversize(3, 10, 20, b"CCC")),
        ]);
        let cache = OversizeCache::with_provider(&provider);

        // Miss on a key from the first file: harvest stops there
        assert_eq!(cache.get_or_harvest(BOOT_A, 1, 10, 20), Some(&b"AAA"[..]));
        assert_eq!(provider.reads("a"), 1);
        assert_eq!(provider.reads("b"), 0);
        assert_eq!(provider.reads("c"), 0);

        // A later miss resumes past the already-harvested file
        assert_eq!(cache.get_or_harvest(BOOT_A, 3, 10, 20), Some(&b"CCC"[..]));
        assert_eq!(provider.reads("a"), 1);
        assert_eq!(provider.reads("b"), 1);
        assert_eq!(provider.reads("c"), 1);

        // Harvested along the way: pure cache hit
        assert_eq!(cache.get_or_harvest(BOOT_A, 2, 10, 20), Some(&b"BBB"[..]));
        assert_eq!(provider.reads("b"), 1);

        // Unknown key exhausts the list once; exhaustion is sticky
        assert_eq!(cache.get_or_harvest(BOOT_A, 99, 0, 0), None);
        let enumerations = provider.enumerations.get();
        assert_eq!(cache.get_or_harvest(BOOT_A, 99, 0, 0), None);
        assert_eq!(provider.enumerations.get(), enumerations);
        assert_eq!(provider.reads("a"), 1);
        assert_eq!(provider.reads("b"), 1);
        assert_eq!(provider.reads("c"), 1);
    }

    #[test]
    fn test_get_or_harvest_skips_covered_files() {
        let provider = CountingProvider::new(vec![
            ("a", synth_tracev3_with_oversize(1, 10, 20, b"AAA")),
            ("b", synth_tracev3_with_oversize(2, 10, 20, b"BBB")),
        ]);
        let cache = OversizeCache::with_provider(&provider);
        cache.mark_covered("a");

        // Only "b" is harvested
        assert_eq!(cache.get_or_harvest(BOOT_A, 2, 10, 20), Some(&b"BBB"[..]));
        assert_eq!(provider.reads("a"), 0);
        assert_eq!(provider.reads("b"), 1);

        // Key 1 lives only in the covered file: definitive miss, never read
        assert_eq!(cache.get_or_harvest(BOOT_A, 1, 10, 20), None);
        assert_eq!(provider.reads("a"), 0);
    }

    #[test]
    fn test_harvest_first_writer_wins_on_duplicate_keys() {
        let provider = CountingProvider::new(vec![
            ("a", synth_tracev3_with_oversize(1, 10, 20, b"FIRST")),
            ("b", synth_tracev3_with_oversize(1, 10, 20, b"SECOND")),
        ]);
        let cache = OversizeCache::with_provider(&provider);

        assert_eq!(cache.get_or_harvest(BOOT_A, 1, 10, 20), Some(&b"FIRST"[..]));
        // Force harvesting of "b" too, then check the entry was not replaced
        assert_eq!(cache.get_or_harvest(BOOT_A, 99, 0, 0), None);
        assert_eq!(provider.reads("b"), 1);
        assert_eq!(cache.get(BOOT_A, 1, 10, 20), Some(&b"FIRST"[..]));
    }
}
