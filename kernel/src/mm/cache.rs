//! Global Buffer / Page Cache
//!
//! Caches file-backed pages keyed by (mount_index, inode, page_offset_in_file).
//! Prevents redundant disk reads and allows pages to be shared between
//! multiple mappings of the same file region.

extern crate alloc;

use alloc::collections::BTreeMap;
use spin::Mutex;

/// Cache key: (mount_index, inode_number, page_aligned_file_offset).
type CacheKey = (usize, u64, u64);

/// A cached physical page.
struct PageCacheEntry {
    /// Physical address of the cached page.
    phys: u64,
    /// Whether the page has been written to (for future writeback).
    dirty: bool,
}

/// Global page cache.
static PAGE_CACHE: Mutex<BTreeMap<CacheKey, PageCacheEntry>> = Mutex::new(BTreeMap::new());

/// Look up a cached page.  Returns the physical address if found.
pub fn lookup(mount_idx: usize, inode: u64, page_offset: u64) -> Option<u64> {
    PAGE_CACHE
        .lock()
        .get(&(mount_idx, inode, page_offset))
        .map(|e| e.phys)
}

/// Insert a page into the cache.
///
/// Increments the page's reference count to represent the cache's own
/// reference.  If the key already exists the old entry is replaced and
/// its cache reference is released.
pub fn insert(mount_idx: usize, inode: u64, page_offset: u64, phys: u64) {
    let mut cache = PAGE_CACHE.lock();
    if let Some(old) = cache.insert(
        (mount_idx, inode, page_offset),
        PageCacheEntry { phys, dirty: false },
    ) {
        // Replaced an existing entry — drop old cache reference.
        crate::mm::refcount::page_ref_dec(old.phys);
    }
    // The cache now holds a reference to this page.
    crate::mm::refcount::page_ref_inc(phys);
}

/// Mark a cached page as dirty (written to).
pub fn mark_dirty(mount_idx: usize, inode: u64, page_offset: u64) {
    if let Some(entry) = PAGE_CACHE.lock().get_mut(&(mount_idx, inode, page_offset)) {
        entry.dirty = true;
    }
}

/// Evict a page from the cache, releasing the cache's reference.
/// Returns the physical address of the evicted page, if any.
pub fn evict(mount_idx: usize, inode: u64, page_offset: u64) -> Option<u64> {
    let mut cache = PAGE_CACHE.lock();
    if let Some(entry) = cache.remove(&(mount_idx, inode, page_offset)) {
        crate::mm::refcount::page_ref_dec(entry.phys);
        Some(entry.phys)
    } else {
        None
    }
}

/// Mark all dirty pages for a given inode as clean.
/// (Actual writeback through VFS would be added in a future milestone.)
pub fn sync_inode(mount_idx: usize, inode: u64) {
    let mut cache = PAGE_CACHE.lock();
    for ((m, i, _), entry) in cache.iter_mut() {
        if *m == mount_idx && *i == inode {
            entry.dirty = false;
        }
    }
}

/// Return cache statistics: (total_entries, dirty_entries).
pub fn stats() -> (usize, usize) {
    let cache = PAGE_CACHE.lock();
    let total = cache.len();
    let dirty = cache.values().filter(|e| e.dirty).count();
    (total, dirty)
}
