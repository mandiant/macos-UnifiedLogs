use std::collections::HashMap;
use uuid::Uuid;

use super::catalog::RawCatalogChunk;
use super::chunks::firehose::flags::RawFormatterFlags;
use super::dsc::RawSharedCacheStrings;
use super::uuidtext::RawUUIDText;

const DYNAMIC_OFFSET_FLAG: u64 = 0x8000_0000;
const LARGE_OFFSET_BASE: u64 = 0x1_0000_0000;
const PERCENT_S: &str = "%s";

/// Result of resolving a firehose entry's format string, library, and process paths.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedStrings<'a> {
    /// The format string, or None if lookup failed (missing UUID, invalid offset).
    pub format_string: Option<&'a str>,
    /// Library/image path, or None if not found.
    pub library: Option<&'a str>,
    /// Process image path, or None if not found.
    pub process: Option<&'a str>,
    /// UUID of the library that provided the format string.
    pub library_uuid: Uuid,
    /// UUID of the main process executable.
    pub process_uuid: Uuid,
    /// Whether the underlying source file (DSC or `UUIDText`) was found.
    /// Used by compat layer to distinguish Level 1 vs Level 2 error messages.
    pub source_found: bool,
}

/// Resolve format string, library path, and process path for a firehose entry.
///
/// Dispatches to one of 4 resolution paths based on formatter flags:
/// `SharedCache`/`LargeSharedCache` > `Absolute` > `UuidRelative` > `MainExe` (default).
#[allow(clippy::too_many_arguments)]
pub fn resolve_strings<'a>(
    format_string_location: u32,
    pc_id: u32,
    formatter: &RawFormatterFlags,
    first_proc_id: u64,
    second_proc_id: u32,
    catalog: &RawCatalogChunk<'a>,
    dsc_files: &'a HashMap<Uuid, RawSharedCacheStrings<'a>>,
    uuidtext_files: &'a HashMap<Uuid, RawUUIDText<'a>>,
) -> ResolvedStrings<'a> {
    let string_offset = u64::from(format_string_location);
    let original_offset = string_offset;

    if formatter.shared_cache || formatter.large_shared_cache != 0 {
        resolve_shared_cache(
            string_offset,
            original_offset,
            formatter,
            first_proc_id,
            second_proc_id,
            catalog,
            dsc_files,
            uuidtext_files,
        )
    } else if formatter.absolute {
        resolve_absolute(
            string_offset,
            original_offset,
            pc_id,
            formatter,
            first_proc_id,
            second_proc_id,
            catalog,
            uuidtext_files,
        )
    } else if formatter.uuid_relative != [0u8; 16] {
        resolve_uuid_relative(
            string_offset,
            original_offset,
            formatter,
            first_proc_id,
            second_proc_id,
            catalog,
            uuidtext_files,
        )
    } else {
        resolve_main_exe(
            string_offset,
            original_offset,
            first_proc_id,
            second_proc_id,
            catalog,
            uuidtext_files,
        )
    }
}

/// Shared cache (DSC) resolution path.
#[allow(clippy::too_many_arguments)]
fn resolve_shared_cache<'a>(
    string_offset: u64,
    original_offset: u64,
    formatter: &RawFormatterFlags,
    first_proc_id: u64,
    second_proc_id: u32,
    catalog: &RawCatalogChunk<'a>,
    dsc_files: &'a HashMap<Uuid, RawSharedCacheStrings<'a>>,
    uuidtext_files: &'a HashMap<Uuid, RawUUIDText<'a>>,
) -> ResolvedStrings<'a> {
    let entry = catalog.get_process_info(first_proc_id, second_proc_id);
    let main_uuid = entry.map_or(Uuid::nil(), |e| e.main_uuid);
    let dsc_uuid = entry.and_then(|e| e.dsc_uuid);

    let effective_offset = compute_shared_cache_offset(string_offset, formatter);
    let is_dynamic = original_offset & DYNAMIC_OFFSET_FLAG != 0;

    let dsc = dsc_uuid.and_then(|uuid| dsc_files.get(&uuid));
    let source_found = dsc.is_some();
    let process = uuidtext_files.get(&main_uuid).and_then(|u| u.image_path());

    // Dynamic offset: format string is "%s", items data carries the actual string.
    // Legacy requires the DSC to be cached before returning "%s"; when the DSC isn't
    // found it falls through to the error path. In compat mode, match that behavior.
    #[cfg(feature = "rewrite-compat")]
    let is_dynamic = is_dynamic && source_found;

    if is_dynamic {
        let (library, library_uuid) = dsc
            .and_then(|d| d.fallback_library_info())
            .map_or((None, Uuid::nil()), |(l, u)| (Some(l), u));
        return ResolvedStrings {
            format_string: Some(PERCENT_S),
            library,
            process,
            library_uuid,
            process_uuid: main_uuid,
            source_found,
        };
    }

    // Try to find the format string in the DSC
    if let Some(dsc) = dsc
        && let Some(result) = dsc.format_string(effective_offset)
    {
        return ResolvedStrings {
            format_string: Some(result.format_string),
            library: Some(result.library_path),
            process,
            library_uuid: result.library_uuid,
            process_uuid: main_uuid,
            source_found,
        };
    }

    // Fallback: invalid offset — still provide library info if possible
    let (library, library_uuid) = dsc
        .and_then(|d| d.fallback_library_info())
        .map_or((None, Uuid::nil()), |(l, u)| (Some(l), u));
    ResolvedStrings {
        format_string: None,
        library,
        process,
        library_uuid,
        process_uuid: main_uuid,
        source_found,
    }
}

/// Main executable resolution path (UUIDText-based, simplest).
fn resolve_main_exe<'a>(
    string_offset: u64,
    original_offset: u64,
    first_proc_id: u64,
    second_proc_id: u32,
    catalog: &RawCatalogChunk<'a>,
    uuidtext_files: &'a HashMap<Uuid, RawUUIDText<'a>>,
) -> ResolvedStrings<'a> {
    let entry = catalog.get_process_info(first_proc_id, second_proc_id);
    let main_uuid = entry.map_or(Uuid::nil(), |e| e.main_uuid);

    let uuidtext = uuidtext_files.get(&main_uuid);
    let source_found = uuidtext.is_some();
    let image_path = uuidtext.and_then(|u| u.image_path());
    let is_dynamic = original_offset & DYNAMIC_OFFSET_FLAG != 0;

    // Legacy requires UUIDText cached before returning "%s" for dynamic offsets.
    #[cfg(feature = "rewrite-compat")]
    let is_dynamic = is_dynamic && source_found;

    let format_string = if is_dynamic {
        Some(PERCENT_S)
    } else {
        uuidtext.and_then(|u| u.format_string(string_offset))
    };

    ResolvedStrings {
        format_string,
        library: image_path,
        process: image_path,
        library_uuid: main_uuid,
        process_uuid: main_uuid,
        source_found,
    }
}

/// Absolute address resolution path.
#[allow(clippy::too_many_arguments)]
fn resolve_absolute<'a>(
    string_offset: u64,
    original_offset: u64,
    pc_id: u32,
    formatter: &RawFormatterFlags,
    first_proc_id: u64,
    second_proc_id: u32,
    catalog: &RawCatalogChunk<'a>,
    uuidtext_files: &'a HashMap<Uuid, RawUUIDText<'a>>,
) -> ResolvedStrings<'a> {
    let absolute_offset = (u64::from(formatter.alt_index) << 32) | u64::from(pc_id);

    let entry = catalog.get_process_info(first_proc_id, second_proc_id);
    let main_uuid = entry.map_or(Uuid::nil(), |e| e.main_uuid);

    // Find the UUID whose load_address range contains absolute_offset
    let library_uuid = entry
        .and_then(|e| {
            e.uuid_info_entries
                .iter()
                .find(|u| {
                    absolute_offset >= u.load_address
                        && absolute_offset <= (u.load_address + u64::from(u.size))
                })
                .map(|u| u.uuid)
        })
        .unwrap_or(Uuid::nil());

    let is_dynamic =
        (original_offset & DYNAMIC_OFFSET_FLAG != 0) || string_offset == absolute_offset;

    let library_uuidtext = uuidtext_files.get(&library_uuid);
    let source_found = library_uuidtext.is_some();
    let library = library_uuidtext.and_then(|u| u.image_path());
    let process = uuidtext_files.get(&main_uuid).and_then(|u| u.image_path());

    // Legacy requires UUIDText cached before returning "%s" for dynamic offsets.
    #[cfg(feature = "rewrite-compat")]
    let is_dynamic = is_dynamic && source_found;

    let format_string = if is_dynamic {
        Some(PERCENT_S)
    } else {
        library_uuidtext.and_then(|u| u.format_string(string_offset))
    };

    ResolvedStrings {
        format_string,
        library,
        process,
        library_uuid,
        process_uuid: main_uuid,
        source_found,
    }
}

/// UUID-relative resolution path.
fn resolve_uuid_relative<'a>(
    string_offset: u64,
    original_offset: u64,
    formatter: &RawFormatterFlags,
    first_proc_id: u64,
    second_proc_id: u32,
    catalog: &RawCatalogChunk<'a>,
    uuidtext_files: &'a HashMap<Uuid, RawUUIDText<'a>>,
) -> ResolvedStrings<'a> {
    let uuid = Uuid::from_bytes(formatter.uuid_relative);

    let entry = catalog.get_process_info(first_proc_id, second_proc_id);
    let main_uuid = entry.map_or(Uuid::nil(), |e| e.main_uuid);

    let is_dynamic = original_offset & DYNAMIC_OFFSET_FLAG != 0;

    let library_uuidtext = uuidtext_files.get(&uuid);
    let source_found = library_uuidtext.is_some();
    let library = library_uuidtext.and_then(|u| u.image_path());
    let process = uuidtext_files.get(&main_uuid).and_then(|u| u.image_path());

    // Legacy requires UUIDText cached before returning "%s" for dynamic offsets.
    #[cfg(feature = "rewrite-compat")]
    let is_dynamic = is_dynamic && source_found;

    let format_string = if is_dynamic {
        Some(PERCENT_S)
    } else {
        library_uuidtext.and_then(|u| u.format_string(string_offset))
    };

    ResolvedStrings {
        format_string,
        library,
        process,
        library_uuid: uuid,
        process_uuid: main_uuid,
        source_found,
    }
}

/// Compute the effective shared cache offset, adjusting for large offsets.
///
/// From legacy `nonactivity.rs:122-143`:
/// - `has_large_offset == 0` → return unchanged
/// - Mismatched `has_large_offset` vs `large_shared_cache / 2` AND NOT `shared_cache`
///   → recovery using `large_shared_cache / 2`
/// - `shared_cache` flag set with `has_large_offset == 1`
///   → `0x10000000 * 8 + string_offset`
/// - Otherwise → `LARGE_OFFSET_BASE * has_large_offset + string_offset`
fn compute_shared_cache_offset(string_offset: u64, formatter: &RawFormatterFlags) -> u64 {
    if formatter.has_large_offset == 0 {
        return string_offset;
    }

    if formatter.has_large_offset != formatter.large_shared_cache / 2 && !formatter.shared_cache {
        let large_offset = formatter.large_shared_cache / 2;
        (LARGE_OFFSET_BASE * u64::from(large_offset)) + string_offset
    } else if formatter.shared_cache && formatter.has_large_offset == 1 {
        0x1000_0000 * 8 + string_offset
    } else {
        (LARGE_OFFSET_BASE * u64::from(formatter.has_large_offset)) + string_offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewrite::chunks::firehose::flags::RawFormatterFlags;
    use test_case::test_case;

    // --- compute_shared_cache_offset tests ---

    #[test_case(0, 0, false, 12345,  12345                          ; "no large offset")]
    #[test_case(2, 4, false, 0x1000, LARGE_OFFSET_BASE * 2 + 0x1000 ; "matching")]
    #[test_case(3, 4, false, 0x1000, LARGE_OFFSET_BASE * 2 + 0x1000 ; "mismatched recovery")]
    #[test_case(1, 0, true,  0x1000, 0x1000_0000 * 8 + 0x1000      ; "shared cache special large offset")]
    #[test_case(2, 4, true,  0x1000, LARGE_OFFSET_BASE * 2 + 0x1000 ; "shared cache large offset")]
    fn test_compute_shared_cache_offset(
        has_large_offset: u16,
        large_shared_cache: u16,
        shared_cache: bool,
        input: u64,
        expected: u64,
    ) {
        let formatter = RawFormatterFlags {
            has_large_offset,
            large_shared_cache,
            shared_cache,
            ..Default::default()
        };
        assert_eq!(compute_shared_cache_offset(input, &formatter), expected);
    }

    // --- resolve_strings tests ---

    #[test]
    fn test_resolve_main_exe_dynamic() {
        // When DYNAMIC_OFFSET_FLAG is set, format_string should be "%s"
        // In compat mode, requires source file to exist (legacy behavior).
        let catalog = RawCatalogChunk::default();
        let dsc_files = HashMap::new();
        let uuidtext_files = HashMap::new();

        let formatter = RawFormatterFlags {
            main_exe: true,
            ..Default::default()
        };

        // format_string_location with MSB set
        let location = 0x8000_0000u32;
        let result = resolve_strings(
            location,
            0,
            &formatter,
            0,
            0,
            &catalog,
            &dsc_files,
            &uuidtext_files,
        );

        #[cfg(not(feature = "rewrite-compat"))]
        assert_eq!(result.format_string, Some("%s"));
        #[cfg(feature = "rewrite-compat")]
        assert_eq!(result.format_string, None); // source file missing → no "%s"
        assert_eq!(result.process_uuid, Uuid::nil());
    }

    #[test]
    fn test_resolve_missing_uuid() {
        // UUID not in maps → None for string fields
        let catalog = RawCatalogChunk::default();
        let dsc_files = HashMap::new();
        let uuidtext_files = HashMap::new();

        let formatter = RawFormatterFlags {
            main_exe: true,
            ..Default::default()
        };

        let result = resolve_strings(
            12345,
            0,
            &formatter,
            99,
            99,
            &catalog,
            &dsc_files,
            &uuidtext_files,
        );

        // No catalog entry, no uuidtext → format_string and paths are None
        assert!(result.format_string.is_none());
        assert!(result.library.is_none());
        assert!(result.process.is_none());
        assert_eq!(result.library_uuid, Uuid::nil());
        assert_eq!(result.process_uuid, Uuid::nil());
    }

    #[test]
    fn test_resolve_shared_cache_dynamic() {
        let catalog = RawCatalogChunk::default();
        let dsc_files = HashMap::new();
        let uuidtext_files = HashMap::new();

        let formatter = RawFormatterFlags {
            shared_cache: true,
            ..Default::default()
        };

        // format_string_location with DYNAMIC_OFFSET_FLAG set
        let location = 0x8000_1234u32;
        let result = resolve_strings(
            location,
            0,
            &formatter,
            0,
            0,
            &catalog,
            &dsc_files,
            &uuidtext_files,
        );

        #[cfg(not(feature = "rewrite-compat"))]
        assert_eq!(result.format_string, Some("%s"));
        #[cfg(feature = "rewrite-compat")]
        assert_eq!(result.format_string, None); // DSC not loaded → no "%s"
    }

    #[test]
    fn test_resolve_uuid_relative_dynamic() {
        let catalog = RawCatalogChunk::default();
        let dsc_files = HashMap::new();
        let uuidtext_files = HashMap::new();

        let formatter = RawFormatterFlags {
            uuid_relative: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            ..Default::default()
        };

        let location = 0x8000_0000u32;
        let result = resolve_strings(
            location,
            0,
            &formatter,
            0,
            0,
            &catalog,
            &dsc_files,
            &uuidtext_files,
        );

        #[cfg(not(feature = "rewrite-compat"))]
        assert_eq!(result.format_string, Some("%s"));
        #[cfg(feature = "rewrite-compat")]
        assert_eq!(result.format_string, None); // UUIDText not loaded → no "%s"
        assert_eq!(
            result.library_uuid,
            Uuid::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        );
    }

    #[test]
    fn test_resolve_absolute_dynamic_when_offsets_equal() {
        // When string_offset == absolute_offset, it's treated as dynamic
        let catalog = RawCatalogChunk::default();
        let dsc_files = HashMap::new();
        let uuidtext_files = HashMap::new();

        let formatter = RawFormatterFlags {
            absolute: true,
            alt_index: 0,
            ..Default::default()
        };

        // pc_id = 102, format_string_location = 102 → string_offset == absolute_offset
        let result = resolve_strings(
            102,
            102,
            &formatter,
            0,
            0,
            &catalog,
            &dsc_files,
            &uuidtext_files,
        );
        #[cfg(not(feature = "rewrite-compat"))]
        assert_eq!(result.format_string, Some("%s"));
        #[cfg(feature = "rewrite-compat")]
        assert_eq!(result.format_string, None); // UUIDText not loaded → no "%s"
    }

    #[test]
    fn test_resolve_dispatch_priority() {
        // shared_cache takes priority over absolute
        let catalog = RawCatalogChunk::default();
        let dsc_files = HashMap::new();
        let uuidtext_files = HashMap::new();

        let formatter = RawFormatterFlags {
            shared_cache: true,
            absolute: true, // should be ignored
            ..Default::default()
        };

        let location = 0x8000_0000u32;
        let result = resolve_strings(
            location,
            0,
            &formatter,
            0,
            0,
            &catalog,
            &dsc_files,
            &uuidtext_files,
        );
        // Should take shared_cache path → dynamic → "%s"
        #[cfg(not(feature = "rewrite-compat"))]
        assert_eq!(result.format_string, Some("%s"));
        #[cfg(feature = "rewrite-compat")]
        assert_eq!(result.format_string, None); // DSC not loaded → no "%s"
    }
}
