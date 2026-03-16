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

/// Pre-populate the page cache for an entire file.
///
/// Reads every 4KB page of the file from disk into PMM-allocated pages
/// and inserts them into the page cache.  Subsequent demand-page faults
/// for this file will hit the cache (instant) instead of reading from
/// disk (slow ATA PIO on WSL2/KVM).
///
/// Returns the number of pages cached.
pub fn prepopulate_file(path: &str) -> usize {
    use crate::vfs;

    let (mount_idx, inode) = match vfs::resolve_path(path) {
        Ok(r) => r,
        Err(_) => return 0,
    };
    let file_size = {
        let mounts = vfs::MOUNTS.lock();
        match mounts[mount_idx].fs.stat(inode) {
            Ok(s) => s.size,
            Err(_) => return 0,
        }
    };

    let page_size = crate::mm::pmm::PAGE_SIZE as u64;
    let mut cached = 0usize;
    let phys_off: u64 = 0xFFFF_8000_0000_0000;

    // Read page-by-page directly into PMM pages (no heap allocation).
    // Each page is read from the filesystem into a PMM-allocated physical
    // page via the higher-half mapping, then inserted into the page cache.
    let mut offset: u64 = 0;
    while offset < file_size {
        let page_off = offset & !0xFFF; // page-align
        if lookup(mount_idx, inode, page_off).is_some() {
            offset = page_off + page_size;
            continue;
        }
        // Stop if PMM is running low — keep 20K pages (80MB) free for kernel ops.
        if crate::mm::pmm::free_page_count() < 20_000 {
            crate::serial_println!("[CACHE] prepopulate stopping: PMM low ({} free pages)",
                crate::mm::pmm::free_page_count());
            break;
        }
        if let Some(phys) = crate::mm::pmm::alloc_page() {
            unsafe {
                core::ptr::write_bytes((phys_off + phys) as *mut u8, 0, page_size as usize);
            }
            let buf = unsafe {
                core::slice::from_raw_parts_mut(
                    (phys_off + phys) as *mut u8, page_size as usize)
            };
            {
                let mounts = vfs::MOUNTS.lock();
                if mounts[mount_idx].fs.read(inode, page_off, buf).is_err() {
                    crate::mm::pmm::free_page(phys);
                    break;
                }
            }
            insert(mount_idx, inode, page_off, phys);
            cached += 1;
        } else {
            break; // OOM
        }

        offset = page_off + page_size;

        // Log progress every 4000 pages (~16MB).
        if cached > 0 && cached % 4000 == 0 {
            crate::serial_println!("[CACHE] prepopulate {}: {} pages ({} MB)",
                path, cached, cached * 4 / 1024);
        }
    }
    cached
}

/// Return cache statistics: (total_entries, dirty_entries).
pub fn stats() -> (usize, usize) {
    let cache = PAGE_CACHE.lock();
    let total = cache.len();
    let dirty = cache.values().filter(|e| e.dirty).count();
    (total, dirty)
}
