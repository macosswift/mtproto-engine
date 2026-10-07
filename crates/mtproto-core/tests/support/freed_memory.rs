//! A global allocator that looks for watched secrets in every heap block as it is freed (or moved by a
//! reallocation). A secret found there was dropped without being wiped.

#![allow(unsafe_code, dead_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

pub const NEEDLE_LEN: usize = 16;
const MAX_NEEDLES: usize = 64;

pub struct FreedMemoryScanner;

#[global_allocator]
static SCANNER: FreedMemoryScanner = FreedMemoryScanner;

static NEEDLES: [[AtomicU64; 2]; MAX_NEEDLES] = [const { [AtomicU64::new(0), AtomicU64::new(0)] }; MAX_NEEDLES];
static NEEDLE_COUNT: AtomicUsize = AtomicUsize::new(0);
static HITS: AtomicU64 = AtomicU64::new(0);
static EVERY_THREAD: AtomicBool = AtomicBool::new(false);
static EXCLUSIVE: Mutex<()> = Mutex::new(());
static THREAD_FILTER: OnceLock<fn() -> bool> = OnceLock::new();

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

fn armed() -> bool {
    if ARMED.try_with(Cell::get).unwrap_or(false) {
        return true;
    }
    EVERY_THREAD.load(Ordering::Acquire) && THREAD_FILTER.get().is_none_or(|filter| filter())
}

/// Limits `arm_every_thread` to the threads `filter` accepts. It must not allocate.
pub fn only_threads(filter: fn() -> bool) {
    let _ = THREAD_FILTER.set(filter);
}

unsafe extern "C" {
    fn pthread_self() -> usize;
    fn pthread_getname_np(thread: usize, name: *mut core::ffi::c_char, length: usize) -> core::ffi::c_int;
}

/// The engine names its threads `mtproto-main`, `mtproto-worker-N` and `mtproto-resolver`.
pub fn is_engine_thread() -> bool {
    let mut name = [0 as core::ffi::c_char; 64];
    let read = unsafe { pthread_getname_np(pthread_self(), name.as_mut_ptr(), name.len()) };
    read == 0 && name[..8].iter().map(|byte| *byte as u8).eq(*b"mtproto-")
}

unsafe fn scan(pointer: *const u8, length: usize) {
    if length < NEEDLE_LEN || !armed() {
        return;
    }
    let count = NEEDLE_COUNT.load(Ordering::Acquire).min(MAX_NEEDLES);
    if count == 0 {
        return;
    }
    for offset in 0..=length - NEEDLE_LEN {
        let low = unsafe { core::ptr::read_unaligned(pointer.add(offset) as *const u64) };
        for (index, needle) in NEEDLES.iter().enumerate().take(count) {
            if low == needle[0].load(Ordering::Relaxed) {
                let high = unsafe { core::ptr::read_unaligned(pointer.add(offset + 8) as *const u64) };
                if high == needle[1].load(Ordering::Relaxed) {
                    HITS.fetch_or(1 << index, Ordering::AcqRel);
                }
            }
        }
    }
}

unsafe impl GlobalAlloc for FreedMemoryScanner {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe {
            scan(pointer, layout.size());
            System.dealloc(pointer, layout);
        }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        unsafe {
            let moved = System.alloc(Layout::from_size_align_unchecked(new_size, layout.align()));
            if !moved.is_null() {
                core::ptr::copy_nonoverlapping(pointer, moved, layout.size().min(new_size));
                scan(pointer, layout.size());
                System.dealloc(pointer, layout);
            }
            moved
        }
    }
}

/// One scan at a time: the watched secrets and the hits are global.
pub struct Watch {
    _exclusive: MutexGuard<'static, ()>,
    names: Vec<&'static str>,
}

pub fn watch() -> Watch {
    let exclusive = EXCLUSIVE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    stop();
    NEEDLE_COUNT.store(0, Ordering::Release);
    HITS.store(0, Ordering::Release);
    Watch { _exclusive: exclusive, names: Vec::with_capacity(MAX_NEEDLES) }
}

impl Watch {
    /// 16-byte windows of `secret` become needles: every 8 bytes of a short secret, every 64 of a long one.
    pub fn secret(&mut self, name: &'static str, secret: &[u8]) {
        assert!(secret.len() >= NEEDLE_LEN, "{name}: secrets shorter than {NEEDLE_LEN} bytes cannot be watched");
        let step = if secret.len() <= 64 { 8 } else { 64 };
        let mut offset = 0;
        while offset + NEEDLE_LEN <= secret.len() {
            self.needle(name, &secret[offset..offset + NEEDLE_LEN]);
            offset += step;
        }
    }

    /// `secret` as num-bigint keeps it: little-endian limbs, so the bytes reversed.
    pub fn big_number(&mut self, name: &'static str, big_endian: &[u8]) {
        let mut reversed = big_endian.to_vec();
        reversed.reverse();
        let mut offset = 0;
        while offset + NEEDLE_LEN <= reversed.len() {
            self.needle(name, &reversed[offset..offset + NEEDLE_LEN]);
            offset += 64;
        }
        reversed.fill(0);
    }

    fn needle(&mut self, name: &'static str, window: &[u8]) {
        let index = NEEDLE_COUNT.load(Ordering::Acquire);
        assert!(index < MAX_NEEDLES, "too many needles");
        NEEDLES[index][0].store(u64::from_ne_bytes(window[..8].try_into().unwrap()), Ordering::Relaxed);
        NEEDLES[index][1].store(u64::from_ne_bytes(window[8..].try_into().unwrap()), Ordering::Relaxed);
        self.names.push(name);
        NEEDLE_COUNT.store(index + 1, Ordering::Release);
    }

    /// Scans what this thread frees until `stop`.
    pub fn arm(&self) {
        ARMED.with(|armed| armed.set(true));
    }

    /// Scans what every thread frees until `stop`.
    pub fn arm_every_thread(&self) {
        EVERY_THREAD.store(true, Ordering::Release);
    }

    pub fn stop(&self) {
        stop();
    }

    pub fn clear_hits(&self) {
        HITS.store(0, Ordering::Release);
    }

    /// The names of the secrets found in freed memory so far.
    pub fn found(&self) -> Vec<&'static str> {
        let hits = HITS.load(Ordering::Acquire);
        let mut names: Vec<&'static str> = self
            .names
            .iter()
            .enumerate()
            .filter(|(index, _)| hits & (1 << index) != 0)
            .map(|(_, name)| *name)
            .collect();
        names.dedup();
        names
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        stop();
        NEEDLE_COUNT.store(0, Ordering::Release);
    }
}

fn stop() {
    EVERY_THREAD.store(false, Ordering::Release);
    let _ = ARMED.try_with(|armed| armed.set(false));
}

/// Frees a heap copy of `value`'s bytes without wiping them, as a forgotten copy would be.
pub fn free_unwiped_copy<T>(value: &T) {
    let size = core::mem::size_of::<T>();
    let mut copy = Vec::<u8>::with_capacity(size);
    unsafe {
        core::ptr::copy_nonoverlapping(value as *const T as *const u8, copy.as_mut_ptr(), size);
        copy.set_len(size);
    }
    drop(copy);
}
