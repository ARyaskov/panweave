//! Cortex-M33 probe of a Panweave Lite water leak sensor.
//!
//! * Default build (`thumbv8m.main-none-eabihf`, `memory-efr32mg22.x`):
//!   the sensor firmware's RAM and flash on an EFR32MG22 with 32 KiB of
//!   RAM. The link fails when `.data` + `.bss` leave less than the stack
//!   reserve. It does **not** run on hardware: there is no radio driver
//!   (RAIL is not linked) and the flash driver is a placeholder whose
//!   writes fail ([`flash::Msc`]).
//! * `--features qemu` (`memory-qemu-an505.x`): the same sensor
//!   commissions with a full Panweave coordinator on an emulated
//!   Cortex-M33 (QEMU `mps2-an505`), reports a leak, loses its parent and
//!   rejoins, restarts from flash; every call into the sensor runs over
//!   a painted stack and the deepest use is printed over semihosting.
//!
//! `scripts/lite_footprint.py` turns both into the report of
//! `docs/lite.md`.

#![no_std]
#![no_main]

mod flash;
#[cfg(feature = "qemu")]
mod scenario;
mod stack_meter;

use core::mem::{MaybeUninit, size_of};

use cortex_m_rt::entry;
use panic_halt as _;
use panweave_lite::sensor::{Inputs, SensorKind};
use panweave_lite::{LiteConfig, LiteDevice};
use panweave_mac::radio::{RxMetadata, TxResult};
use panweave_mac::service::MacAction;
use panweave_security::cipher::SoftwareAes;
use panweave_storage::nor_flash::NorFlashStore;
use panweave_testkit::TestRng;
use panweave_types::ExtendedAddress;
use panweave_types::time::Instant;

/// The sensor's flash: the MSC on the EFR32MG22, RAM in QEMU.
#[cfg(not(feature = "qemu"))]
pub type Flash = flash::Msc;
/// The sensor's flash: the MSC on the EFR32MG22, RAM in QEMU.
#[cfg(feature = "qemu")]
pub type Flash = flash::RamFlash;

/// The sensor.
pub type Lite = LiteDevice<SoftwareAes, TestRng, NorFlashStore<Flash>>;

/// Sizes of the sensor's parts on this target, read by
/// `scripts/lite_footprint.py` (the order of
/// `panweave_lite::footprint::components`).
#[unsafe(no_mangle)]
#[used]
static LITE_SIZES: [u32; 15] = {
    let c = panweave_lite::footprint::components::<SoftwareAes, TestRng, NorFlashStore<Flash>>;
    let _ = c;
    [
        size_of::<Lite>() as u32,
        size_of::<panweave_lite::LiteStack<SoftwareAes, TestRng, NorFlashStore<Flash>>>() as u32,
        size_of::<panweave_mac::service::MacService<panweave_mac::service::EndDeviceMac>>() as u32,
        size_of::<panweave_runtime::ProfileNwk<SoftwareAes, TestRng, panweave_lite::SleepySensor>>() as u32,
        size_of::<panweave_runtime::ProfileAps<SoftwareAes, panweave_lite::SleepySensor>>() as u32,
        size_of::<panweave_runtime::ProfileZdo<panweave_lite::SleepySensor>>() as u32,
        size_of::<
            panweave_runtime::ProfileZcl<
                panweave_lite::SleepySensor,
                { panweave_lite::ENDPOINTS },
                { panweave_lite::ENDPOINT_CLUSTERS },
                { panweave_lite::CLUSTER_ATTRIBUTES },
            >,
        >() as u32,
        size_of::<
            panweave_runtime::ProfileCluster<
                panweave_lite::SleepySensor,
                { panweave_lite::CLUSTER_ATTRIBUTES },
            >,
        >() as u32,
        size_of::<panweave_zcl::attribute::Attribute>() as u32,
        size_of::<NorFlashStore<Flash>>() as u32,
        size_of::<SoftwareAes>() as u32,
        size_of::<panweave_runtime::StackEvent>() as u32,
        size_of::<panweave_bdb::Bdb>() as u32,
        size_of::<panweave_lite::ZoneReporter>() as u32,
        size_of::<panweave_runtime::Stack<SoftwareAes, TestRng, panweave_storage::MemoryStorage<64, 128>>>() as u32,
    ]
};

/// The sensor, in `.bss` (`MaybeUninit`: a zero-initialised `Option`
/// would put it in `.data`).
static mut DEVICE: MaybeUninit<Lite> = MaybeUninit::uninit();

/// The sensor's configuration.
pub fn config(ieee: u64) -> LiteConfig {
    let mut c = LiteConfig::new(ExtendedAddress(ieee), SensorKind::WaterLeak);
    c.manufacturer = b"Panweave";
    c.model = b"Lite leak";
    c
}

// The sensor's entry points, never inlined so that the firmware and the
// QEMU scenario run the same frames below them.

/// Builds the sensor in place.
#[inline(never)]
pub fn lite_build(slot: &mut MaybeUninit<Lite>, ieee: u64, storage: NorFlashStore<Flash>) -> &mut Lite {
    match Lite::new_in(slot, &config(ieee), TestRng::seed(ieee), storage) {
        Ok(d) => d,
        Err(_) => halt(),
    }
}

/// Restores the sensor.
#[inline(never)]
pub fn lite_initialize(d: &mut Lite, inputs: Inputs) {
    let _ = d.initialize(inputs);
}

/// Network steering.
#[inline(never)]
pub fn lite_commission(d: &mut Lite) {
    let _ = d.start_commissioning();
}

/// A received frame.
#[inline(never)]
pub fn lite_rx(d: &mut Lite, frame: &[u8], meta: RxMetadata) {
    d.on_radio_frame(frame, meta);
}

/// A transmission finished.
#[inline(never)]
pub fn lite_tx_done(d: &mut Lite, r: TxResult) {
    d.on_tx_complete(Ok(r));
}

/// The next radio action.
#[inline(never)]
pub fn lite_action(d: &mut Lite) -> Option<MacAction> {
    d.next_radio_action()
}

/// Timers.
#[inline(never)]
pub fn lite_poll(d: &mut Lite, now: Instant) {
    d.poll(now);
}

/// Sensor inputs.
#[inline(never)]
pub fn lite_inputs(d: &mut Lite, inputs: Inputs) {
    d.set_inputs(inputs);
}

/// Drains the application events.
#[inline(never)]
pub fn lite_events(d: &mut Lite) -> usize {
    let mut n = 0;
    while d.next_event().is_some() {
        n += 1;
    }
    n
}

fn halt() -> ! {
    loop {
        cortex_m::asm::wfi();
    }
}

#[entry]
fn main() -> ! {
    #[cfg(feature = "qemu")]
    scenario::run();
    #[cfg(not(feature = "qemu"))]
    firmware();
}

/// The sensor firmware's skeleton (link build).
#[cfg(not(feature = "qemu"))]
fn firmware() -> ! {
    // The IEEE address comes from "hardware" so the optimizer cannot fold
    // the configuration away.
    let ieee = u64::from(cortex_m::register::msp::read()) | 0x00DD_0000_0000_0000;
    let Ok(storage) = NorFlashStore::new(flash::Msc, flash::STORE_BASE, flash::STORE_LEN) else {
        // No flash driver yet: see flash::Msc.
        halt();
    };
    // SAFETY: `main` runs once, before any other access to `DEVICE`, and
    // holds the only reference to it from here on.
    let slot = unsafe { &mut *(&raw mut DEVICE) };
    let d = lite_build(slot, ieee, storage);
    lite_initialize(d, Inputs::default());
    lite_commission(d);
    let mut ms = 0u64;
    loop {
        while let Some(a) = lite_action(d) {
            if let MacAction::Transmit { .. } = a {
                lite_tx_done(
                    d,
                    TxResult {
                        acked: false,
                        frame_pending: false,
                        timestamp_us: None,
                    },
                );
            }
        }
        lite_events(d);
        ms = ms.wrapping_add(250);
        lite_poll(d, Instant::from_millis(ms));
        if cortex_m::peripheral::SCB::is_pendsv_pending() {
            lite_inputs(
                d,
                Inputs {
                    alarm: true,
                    ..Inputs::default()
                },
            );
        }
        cortex_m::asm::wfi();
    }
}
