//! Target memory measurements: the main stack's high-water mark and the
//! heap.
//!
//! # Main stack layout (esp-hal 1.2.1, `ld/sections/stack.x`)
//!
//! The main stack is the `.stack` section, the last thing in the `RWDATA`
//! region: it grows down from `_stack_start` (the end of RWDATA) to
//! `_stack_end` (the end of `.bss`). esp-hal places the
//! `stack-protector` guard word `__stack_chk_guard` at `_stack_end` plus
//! `ESP_HAL_CONFIG_STACK_GUARD_OFFSET` (60 by default) and watches it with
//! a debug watchpoint (`stack-guard-monitoring`). Interrupt handlers run
//! on the same stack (RISC-V, no separate interrupt stack in esp-hal).
//!
//! # Watermark
//!
//! [`StackMonitor::paint`] fills the unused part of the stack — from the
//! word after the guard up to 1 KiB below the current stack pointer —
//! with a pattern, once, early in `main`, inside a critical section so no
//! interrupt frame lives in the painted range while it is written. Later,
//! [`StackMonitor::peak`] scans upwards from the bottom for the first word
//! that no longer holds the pattern: everything above it has been used.
//! The scan only reads. The result is a lower bound of the true peak (a
//! frame that reserved stack without writing it is not seen, and use
//! before painting is not counted except for `main`'s own frame), which is
//! how it is reported.
//!
//! Only the linker-provided symbols are used; no address is guessed. The
//! painted words are below every live frame at the time (the margin
//! covers the painting code's own frame), and the guard word is never
//! written.

use core::ptr::addr_of;

/// The fill pattern.
const PAINT: u32 = 0xA5C3_5A3C;
/// Kept free below the stack pointer while painting, octets.
const MARGIN: usize = 1024;

unsafe extern "C" {
    static _stack_start: u32;
    static _stack_end: u32;
    static __stack_chk_guard: u32;
}

/// The main stack's bounds and watermark.
#[derive(Clone, Copy, Debug)]
pub struct StackMonitor {
    /// Lowest painted word.
    bottom: usize,
    /// Highest address of the stack (exclusive).
    top: usize,
    /// End of the painted range (exclusive).
    painted_to: usize,
}

impl StackMonitor {
    /// Paints the unused stack. Call once, early in `main`.
    #[inline(never)]
    pub fn paint() -> Self {
        // Only the linker symbols' addresses are used; the symbols are
        // never read or written through them.
        let (top, end, guard) = (
            addr_of!(_stack_start) as usize,
            addr_of!(_stack_end) as usize,
            addr_of!(__stack_chk_guard) as usize,
        );
        let bottom = (guard.max(end) + 4 + 3) & !3;
        let mut painted_to = bottom;
        critical_section::with(|_| {
            // The deepest live frame is this closure's: stay MARGIN below
            // a local of it.
            let marker = 0u32;
            let sp = core::ptr::from_ref(&marker) as usize;
            let limit = sp.saturating_sub(MARGIN) & !3;
            let mut p = bottom;
            while p < limit {
                // SAFETY: `p` is word aligned and inside the `.stack`
                // section between the guard word (excluded) and MARGIN
                // octets below the current stack pointer: memory no live
                // frame uses, with interrupts disabled so none can start
                // using it while it is written.
                unsafe { (p as *mut u32).write_volatile(PAINT) };
                p += 4;
            }
            painted_to = p;
            core::hint::black_box(&marker);
        });
        StackMonitor {
            bottom,
            top,
            painted_to,
        }
    }

    /// The stack's size, octets.
    pub fn size(&self) -> u32 {
        u32::try_from(self.top.saturating_sub(self.bottom)).unwrap_or(u32::MAX)
    }

    /// The deepest use seen, octets from the top (a lower bound).
    pub fn peak(&self) -> u32 {
        let mut p = self.bottom;
        while p < self.painted_to {
            // SAFETY: reading an aligned word inside the `.stack` section
            // (below `painted_to`, which never exceeds the region).
            let w = unsafe { (p as *const u32).read_volatile() };
            if w != PAINT {
                break;
            }
            p += 4;
        }
        u32::try_from(self.top.saturating_sub(p)).unwrap_or(u32::MAX)
    }
}

/// Heap size, in use, and the most ever in use (octets).
pub fn heap() -> (u32, u32, u32) {
    let s = esp_alloc::HEAP.stats();
    let n = |v: usize| u32::try_from(v).unwrap_or(u32::MAX);
    (n(s.size), n(s.current_usage), n(s.max_usage))
}
