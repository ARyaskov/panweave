//! Startup breadcrumbs in RTC RAM; no Flash reads or writes.

use core::ptr::{addr_of, addr_of_mut};
use panweave_hub::boot::StartupStage;

// esp-hal zeros persistent RTC RAM on power-on and retains it on warm
// resets. u32 accepts every bit pattern; the marker also validates magic
// and a complementary stage byte before interpreting retained data.
#[esp_hal::ram(unstable(rtc_fast, persistent))]
static mut CHECKPOINT: u32 = 0;

/// Starts a new boot and returns the preceding boot's checked checkpoint.
pub fn begin() -> Option<StartupStage> {
    // SAFETY: a single aligned u32 in linker-managed RTC RAM, read only
    // from main; all bit patterns are valid, and no interrupt accesses it.
    let previous = unsafe { addr_of!(CHECKPOINT).read_volatile() };
    mark(StartupStage::Entry);
    StartupStage::from_marker(previous)
}

/// Records the next operation before executing it.
pub fn mark(stage: StartupStage) {
    // SAFETY: the same main-only aligned RTC word as in begin(). An
    // interrupted/corrupted write is rejected when the marker is decoded.
    unsafe { addr_of_mut!(CHECKPOINT).write_volatile(stage.marker()) };
}
