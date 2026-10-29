//! Stack painting: fills the free stack below the caller with a pattern,
//! runs a closure, and finds the deepest word it overwrote.

#![allow(dead_code)]

/// The painted span below the current stack pointer.
pub const SPAN: usize = 24 * 1024;
const PATTERN: u32 = 0xA5C3_5A3C;
/// Words kept clear below the stack pointer for the painting code itself.
const GUARD: usize = 64;

/// Runs `f` over a painted stack; returns its result and the octets of
/// stack it used below the caller's stack pointer.
#[inline(never)]
pub fn measure<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let sp = cortex_m::register::msp::read() as usize;
    let top = sp - GUARD;
    let bottom = top - SPAN;
    // SAFETY: the words between `bottom` and `top` are below the stack
    // pointer (free stack; no interrupt runs in the probe) and inside the
    // stack region the linker script reserves.
    unsafe {
        let mut p = bottom as *mut u32;
        while (p as usize) < top {
            core::ptr::write_volatile(p, PATTERN);
            p = p.add(1);
        }
    }
    let r = f();
    let mut lowest = top;
    // SAFETY: as above; read only.
    unsafe {
        let mut p = bottom as *const u32;
        while (p as usize) < top {
            if core::ptr::read_volatile(p) != PATTERN {
                lowest = p as usize;
                break;
            }
            p = p.add(1);
        }
    }
    (r, sp - lowest)
}
