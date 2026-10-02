#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};

thread_local! {
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
    static BASE: Cell<isize> = const { Cell::new(0) };
}

static INSTALLED: AtomicBool = AtomicBool::new(false);

pub struct TrackingAlloc;

fn note(delta: isize) {
    INSTALLED.store(true, Ordering::Relaxed);
    let _ = LIVE.try_with(|live| {
        let value = live.get() + delta;
        live.set(value);
        let _ = PEAK.try_with(|peak| {
            if value > peak.get() {
                peak.set(value);
            }
        });
    });
}

unsafe impl GlobalAlloc for TrackingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            note(layout.size() as isize);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            note(layout.size() as isize);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        note(-(layout.size() as isize));
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            note(new_size as isize - layout.size() as isize);
        }
        moved
    }
}

pub fn is_tracking() -> bool {
    INSTALLED.load(Ordering::Relaxed)
}

pub fn reset_peak() {
    let live = LIVE.with(Cell::get);
    BASE.with(|base| base.set(live));
    PEAK.with(|peak| peak.set(live));
}

pub fn peak_since_reset() -> usize {
    let base = BASE.with(Cell::get);
    PEAK.with(Cell::get).saturating_sub(base).max(0) as usize
}

pub fn live_since_reset() -> isize {
    LIVE.with(Cell::get) - BASE.with(Cell::get)
}
