use std::sync::{Arc, RwLock};

use uuid::Uuid;

use crate::rewrite::logarchive::{load_file_buffers_by_uuid, load_uuidtext_buffers};

use super::traits::{FileProvider, StringCache};

type BufferSet = Arc<Vec<(Uuid, Vec<u8>)>>;

/// Thread-safe string-data cache used by the rewrite compatibility API.
///
/// This mirrors the legacy `MemoryStringCache` call pattern while storing the raw
/// rewrite buffers needed to materialize DSC and UUIDText lookup maps.
#[derive(Clone, Debug, Default)]
pub struct MemoryStringCache {
    dsc: Arc<RwLock<Option<BufferSet>>>,
    uuidtext: Arc<RwLock<Option<BufferSet>>>,
}

impl MemoryStringCache {
    pub fn new() -> Self {
        Self::default()
    }
}

impl StringCache for MemoryStringCache {
    fn dsc_buffers(&self, provider: &impl FileProvider) -> BufferSet {
        if let Some(buffers) = self.dsc.read().ok().and_then(|guard| guard.clone()) {
            return buffers;
        }

        let buffers = Arc::new(load_file_buffers_by_uuid(&provider.dsc_dir()));
        if let Ok(mut guard) = self.dsc.write() {
            if let Some(existing) = guard.as_ref() {
                return Arc::clone(existing);
            }
            *guard = Some(Arc::clone(&buffers));
        }
        buffers
    }

    fn uuidtext_buffers(&self, provider: &impl FileProvider) -> BufferSet {
        if let Some(buffers) = self.uuidtext.read().ok().and_then(|guard| guard.clone()) {
            return buffers;
        }

        let buffers = Arc::new(load_uuidtext_buffers(&provider.uuidtext_root()));
        if let Ok(mut guard) = self.uuidtext.write() {
            if let Some(existing) = guard.as_ref() {
                return Arc::clone(existing);
            }
            *guard = Some(Arc::clone(&buffers));
        }
        buffers
    }
}
