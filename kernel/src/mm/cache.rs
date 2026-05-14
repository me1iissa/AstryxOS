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

/// Look up a cached page and atomically acquire a guard reference on it.
///
/// The reference count is incremented while the cache lock is still held, so
/// the caller's view of the returned physical address is guaranteed to be alive
/// until a matching `page_ref_dec` is issued.  Without this atomicity, a bare
/// `lookup` + later `page_ref_inc` pair admits a window in which:
///
///   1. A concurrent `cache::insert` collision evicts the old entry and drops
///      the cache's own reference (`page_ref_dec` in `insert`).
///   2. A sibling process's `munmap` / `execve` teardown drops the last PTE
///      reference, driving the refcount to zero.
///   3. `pmm::alloc_page` on a third CPU recycles the frame into a different
///      VMA before the faulting CPU reaches its own `page_ref_inc`.
///
/// The faulting CPU would then install a stale PTE pointing at a recycled
/// frame, aliasing two unrelated virtual address spaces against the same
/// physical frame.  Holding the cache lock across the refcount increment
/// collapses the race window to zero: no concurrent insert can evict the entry,
/// and therefore no munmap can drive the refcount to zero, while this function
/// executes.
///
/// Per Intel SDM Vol. 3A §4.10.5 (page-level coherence requirements) and
/// POSIX mmap(2) MAP_SHARED visibility semantics, every path that installs
/// a PTE must ensure the target frame is alive at the moment of install and
/// remains so until the PTE is removed.  This function satisfies that
/// requirement for the cache-hit path.
///
/// # Caller contract
///
/// The caller MUST release the acquired reference via `page_ref_dec` once it
/// has either:
///   (a) installed a PTE whose own refcount now covers the frame — the acquired
///       guard ref is then redundant and must be dropped; or
///   (b) aborted before PTE installation (OOM, error, etc.) — the acquired
///       guard ref is the last reference and dropping it may free the frame.
///
/// In the alias arm (MAP_SHARED or PROT_READ), the guard ref IS the PTE ref
/// (no separate `page_ref_inc` before `map_page_in` is needed or correct).
/// In the private-copy arm the guard ref is purely protective: after the
/// `copy_nonoverlapping` completes, drop the guard via `page_ref_dec` because
/// the installed PTE refers to `private_phys`, not `cached_phys`.
pub fn lookup_and_acquire(mount_idx: usize, inode: u64, page_offset: u64) -> Option<u64> {
    let cache = PAGE_CACHE.lock();
    let phys = cache.get(&(mount_idx, inode, page_offset))?.phys;
    // Bump the refcount while the cache lock is still held.  This prevents any
    // concurrent `cache::insert` (which holds the same lock before its own
    // `page_ref_dec` on eviction) from driving the count to zero between our
    // lookup and the caller's eventual PTE install.
    crate::mm::refcount::page_ref_inc(phys);
    Some(phys)
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
        // Intentional discard: rc may still be > 0 (user PTEs keep
        // their own references); we only dec the cache's reference.
        let _ = crate::mm::refcount::page_ref_dec(old.phys);
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
        // Caller takes ownership of the phys frame; freeing it (with proper
        // shootdown) is the caller's responsibility.  Here we only release
        // the cache's reference.
        let _ = crate::mm::refcount::page_ref_dec(entry.phys);
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
/// Reads are issued in multi-megabyte bursts so each `Filesystem::read` call
/// amortises its inode lookup, cluster-chain walk, and lock acquisitions over
/// many pages — and the underlying block driver coalesces sequential clusters
/// into a small number of large multi-sector requests instead of one per
/// page.  After the burst arrives, we copy each page into a freshly allocated
/// PMM frame so the page cache continues to own per-page physical frames as
/// the rest of the VM expects.
///
/// Returns the number of pages cached.
pub fn prepopulate_file(path: &str) -> usize {
    use crate::vfs;

    let (mount_idx, inode) = match vfs::resolve_path(path) {
        Ok(r) => r,
        Err(_) => return 0,
    };
    // Snapshot the FS handle and drop MOUNTS before any FS dispatch:
    // stat/read here could fault on the chunk buffer's kernel pages and
    // re-enter the PF handler, which itself needs MOUNTS (#82).
    let fs: alloc::sync::Arc<dyn vfs::FileSystemOps> = {
        let mounts = vfs::MOUNTS.lock();
        match mounts.get(mount_idx) {
            Some(m) => m.fs.clone(),
            None => return 0,
        }
    };
    let file_size = match fs.stat(inode) {
        Ok(s) => s.size,
        Err(_) => return 0,
    };

    let page_size = crate::mm::pmm::PAGE_SIZE as u64;
    let mut cached = 0usize;
    let phys_off: u64 = 0xFFFF_8000_0000_0000;

    // Read in 2 MiB bursts.  Sized to match the BlockDevice multi-sector
    // batch window so each `read` translates into a small number of
    // underlying multi-sector requests (the block driver caps each request
    // at 1 MiB to keep the contiguous-buffer requirement modest, so a
    // 2 MiB burst becomes two adjacent virtio requests).  This amortises
    // the per-request KVM/MMIO round-trip cost (typical 3-5 ms per virtio
    // request) over many pages — the 38k-page libxul prepopulate compresses
    // into ~75 bursts (~150 underlying requests) instead of the original
    // 38k page-by-page reads.
    const CHUNK_PAGES: usize = 512;
    const CHUNK_BYTES: usize = CHUNK_PAGES * 4096;
    let mut chunk_buf: alloc::vec::Vec<u8> = alloc::vec![0u8; CHUNK_BYTES];

    let mut offset: u64 = 0;
    while offset < file_size {
        // Stop if PMM is running low — keep 20K pages (80MB) free for kernel ops.
        if crate::mm::pmm::free_page_count() < 20_000 {
            crate::serial_println!("[CACHE] prepopulate stopping: PMM low ({} free pages)",
                crate::mm::pmm::free_page_count());
            break;
        }

        let chunk_start = offset & !(CHUNK_BYTES as u64 - 1); // CHUNK-aligned
        let chunk_remaining = file_size.saturating_sub(chunk_start);
        let this_chunk = core::cmp::min(chunk_remaining as usize, CHUNK_BYTES);

        // If every page in this chunk is already cached, skip the disk read.
        let mut all_cached = true;
        for page_idx in 0..((this_chunk + 4095) / 4096) {
            let page_off = chunk_start + (page_idx as u64) * page_size;
            if lookup(mount_idx, inode, page_off).is_none() {
                all_cached = false;
                break;
            }
        }
        if all_cached {
            offset = chunk_start + this_chunk as u64;
            continue;
        }

        // Issue one filesystem read for the entire chunk.  The FAT32 driver
        // detects the contiguous cluster run, computes the matching disk
        // sector range, and issues large multi-sector block-device calls —
        // one virtio request per up-to-1 MiB-aligned segment of the burst.
        // (`fs` was snapshotted above; MOUNTS is not held during the read.)
        let read_buf = &mut chunk_buf[..this_chunk];
        if fs.read(inode, chunk_start, read_buf).is_err() {
            break;
        }

        // Split the chunk into 4 KiB pages, allocating a PMM frame for each
        // and inserting it into the page cache.
        let mut page_off_in_chunk = 0usize;
        while page_off_in_chunk < this_chunk {
            let page_off = chunk_start + page_off_in_chunk as u64;
            if lookup(mount_idx, inode, page_off).is_some() {
                page_off_in_chunk += page_size as usize;
                continue;
            }
            if let Some(phys) = crate::mm::pmm::alloc_page() {
                let copy_len = core::cmp::min(
                    page_size as usize,
                    this_chunk - page_off_in_chunk,
                );
                let dst = (phys_off + phys) as *mut u8;
                // SAFETY: PMM hands out an exclusive 4 KiB physical frame.
                // The higher-half identity map covers it, and the page cache
                // is the sole owner once we insert.
                unsafe {
                    if copy_len < page_size as usize {
                        core::ptr::write_bytes(dst, 0, page_size as usize);
                    }
                    core::ptr::copy_nonoverlapping(
                        chunk_buf.as_ptr().add(page_off_in_chunk),
                        dst,
                        copy_len,
                    );
                }
                insert(mount_idx, inode, page_off, phys);
                cached += 1;
            } else {
                // OOM — bail out of the inner loop; outer loop will hit the
                // free-page guard and exit on the next iteration.
                break;
            }
            page_off_in_chunk += page_size as usize;

            // Log progress every 4000 pages (~16MB).
            if cached > 0 && cached % 4000 == 0 {
                crate::serial_println!("[CACHE] prepopulate {}: {} pages ({} MB)",
                    path, cached, cached * 4 / 1024);
            }
        }

        offset = chunk_start + this_chunk as u64;
    }
    cached
}

/// Conditionally evict a cache entry, but only if the stored physical address
/// matches `expected_phys`.
///
/// This is used by the demand-paging path to reclaim a redundant frame when a
/// concurrent `cache::insert` on the same (mount, inode, offset) key has
/// already replaced the entry with a different physical address.  A plain
/// `evict` would incorrectly discard the winner's entry and leak a reference.
///
/// Returns `true` if the entry was found, matched, and removed.
pub fn evict_if_phys(
    mount_idx: usize,
    inode: u64,
    page_offset: u64,
    expected_phys: u64,
) -> bool {
    let key = (mount_idx, inode, page_offset);
    let mut cache = PAGE_CACHE.lock();
    // Peek before removing so we don't evict a different winner's entry.
    let matches = cache
        .get(&key)
        .map(|e| e.phys == expected_phys)
        .unwrap_or(false);
    if matches {
        cache.remove(&key);
        // Release the cache's reference to the evicted frame.
        let _ = crate::mm::refcount::page_ref_dec(expected_phys);
        true
    } else {
        false
    }
}

/// Return cache statistics: (total_entries, dirty_entries).
pub fn stats() -> (usize, usize) {
    let cache = PAGE_CACHE.lock();
    let total = cache.len();
    let dirty = cache.values().filter(|e| e.dirty).count();
    (total, dirty)
}
