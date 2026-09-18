//! Links a complete Panweave router (facade `Node` with an On/Off Light
//! endpoint, a null radio and RAM storage) so that `arm-none-eabi-size`
//! or the `scripts/elf_size.py` helper report the stack's ROM (`.text` +
//! `.rodata`) and RAM (`.data` + `.bss`) footprint on a Cortex-M4F. The
//! `Node` lives in `.bss` as a `static` so its size shows up there
//! rather than on the stack. Nothing runs usefully: the loop drives the
//! stack with a clock that never advances.

#![no_std]
#![no_main]

use core::mem::{MaybeUninit, size_of};

use cortex_m_rt::entry;
use panic_halt as _;
use panweave::bdb::Bdb;
use panweave::endpoints;
use panweave::mac::radio::TxResult;
use panweave::mac::service::{MacAction, MacService};
use panweave::runtime::{
    EVENT_CAPACITY, Stack, StackAps, StackCluster, StackEndpoint, StackEvent, StackNwk, StackZcl,
    StackZdo,
};
use panweave::security::cipher::SoftwareAes;
use panweave::storage::MemoryStorage;
use panweave::types::time::Instant;
use panweave::types::{Endpoint, ExtendedAddress};
use panweave::zcl::attribute::Attribute;
use panweave::zcl::cluster::ClusterState;
use panweave::{Node, Router};
use panweave_testkit::TestRng;

type Probe = Node<SoftwareAes, TestRng, MemoryStorage<32, 128>>;

/// Sizes of the stack's components on this target, for
/// `scripts/elf_size.py --components` (which knows this order).
#[unsafe(no_mangle)]
#[used]
static PANWEAVE_SIZES: [u32; 14] = [
    size_of::<Probe>() as u32,
    size_of::<Stack<SoftwareAes, TestRng, MemoryStorage<32, 128>>>() as u32,
    size_of::<MacService>() as u32,
    size_of::<StackNwk<SoftwareAes, TestRng>>() as u32,
    size_of::<StackAps<SoftwareAes>>() as u32,
    size_of::<StackZdo>() as u32,
    size_of::<StackZcl>() as u32,
    size_of::<StackEndpoint>() as u32,
    size_of::<StackCluster>() as u32,
    size_of::<ClusterState>() as u32,
    size_of::<Attribute>() as u32,
    size_of::<MemoryStorage<32, 128>>() as u32,
    size_of::<StackEvent>() as u32 * EVENT_CAPACITY as u32,
    size_of::<Bdb>() as u32,
];

/// The whole stack, in `.bss` (uninitialised until `main` builds it; a
/// zero-initialised `Option` would land the whole thing in `.data`).
static mut NODE: MaybeUninit<Probe> = MaybeUninit::uninit();

#[entry]
fn main() -> ! {
    // The IEEE address comes from "hardware" so the optimizer cannot fold
    // the configuration away.
    let ieee = ExtendedAddress(u64::from(cortex_m::register::msp::read()) | 0x00DD_0000_0000_0000);
    let mut node: Probe = Router::new(ieee)
        .identity(b"Panweave", b"Probe")
        .build::<SoftwareAes, _, _>(TestRng::seed(1), MemoryStorage::new());
    let (desc, ep) = endpoints::on_off_light(Endpoint(1)).unwrap();
    node.add_endpoint(desc, ep).unwrap();
    let _ = node.initialize();
    let _ = node.steer();
    // SAFETY: `main` runs once, before any other access to `NODE`, and
    // holds the only reference to it from here on.
    let node: &mut Probe = unsafe {
        let slot = &raw mut NODE;
        (*slot).write(node)
    };
    let mut ms = 0u64;
    loop {
        node.poll(Instant::from_millis(ms));
        while let Some(action) = node.next_radio_action() {
            if let MacAction::Transmit { .. } = action {
                node.on_tx_complete(Ok(TxResult {
                    acked: false,
                    frame_pending: false,
                    timestamp_us: None,
                }));
            }
        }
        while let Some(_event) = node.next_event() {}
        ms = ms.wrapping_add(250);
        cortex_m::asm::wfi();
    }
}
