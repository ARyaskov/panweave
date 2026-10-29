//! QEMU scenario: the sensor commissions with a full Panweave coordinator
//! (Trust Center) over a two-radio medium, reports a leak, loses its
//! parent and rejoins, and restarts from its flash; the stack used by
//! every call into the sensor is measured and printed.

use core::mem::MaybeUninit;

use cortex_m_semihosting::{debug, hprintln};
use panweave_lite::sensor::Inputs;
use panweave_lite::{Delivery, SENSOR_ENDPOINT};
use panweave_mac::radio::{RxMetadata, TxResult};
use panweave_mac::service::{MacAction, MacServiceConfig};
use panweave_runtime::{Stack, StackConfig};
use panweave_security::cipher::SoftwareAes;
use panweave_storage::MemoryStorage;
use panweave_storage::nor_flash::NorFlashStore;
use panweave_testkit::TestRng;
use panweave_types::time::Instant;
use panweave_types::{Channel, DeviceId, Endpoint, ExtendedAddress, Key128, LogicalDeviceType, ProfileId};
use panweave_zcl::Role;
use panweave_zcl::clusters::{ias_zone, power_configuration};
use panweave_zdo::descriptor::SimpleDescriptor;

use crate::flash::{RamFlash, STORE_LEN};
use crate::stack_meter::measure;
use crate::{DEVICE, Lite};

type Coord = Stack<SoftwareAes, TestRng, MemoryStorage<64, 128>>;

const COORD: u64 = 0x00AB_0000_0000_0001;
const SENSOR: u64 = 0x00AB_0000_0000_0010;

#[unsafe(link_section = ".bigram")]
static mut COORDINATOR: MaybeUninit<Coord> = MaybeUninit::uninit();
#[unsafe(link_section = ".bigram")]
static mut FLASH: [u8; STORE_LEN as usize] = [0xff; STORE_LEN as usize];

/// Deepest stack use per phase and entry point.
#[derive(Default)]
struct Peaks {
    phase: [usize; 6],
    entry: [usize; 9],
}

const PHASES: [&str; 6] = [
    "construction",
    "initialization",
    "commissioning",
    "report",
    "parent loss and rejoin",
    "restart from flash",
];
const ENTRIES: [&str; 9] = [
    "new", "initialize", "commission", "on_radio_frame", "on_tx_complete",
    "next_radio_action", "poll", "set_inputs", "next_event",
];

struct World {
    coord: &'static mut Coord,
    lite: &'static mut Lite,
    now: u64,
    coord_channel: Option<Channel>,
    lite_channel: Option<Channel>,
    link: bool,
    peaks: Peaks,
    phase: usize,
}

impl World {
    fn note(&mut self, entry: usize, depth: usize) {
        let p = &mut self.peaks;
        p.entry[entry] = p.entry[entry].max(depth);
        p.phase[self.phase] = p.phase[self.phase].max(depth);
    }

    fn meta(channel: Option<Channel>) -> RxMetadata {
        RxMetadata {
            lqi: 200,
            rssi_dbm: -40,
            timestamp_us: None,
            acked_by_hardware: false,
            channel,
        }
    }

    fn reaches(&self) -> bool {
        self.link && self.coord_channel == self.lite_channel
    }

    /// Moves frames until both sides are quiet.
    fn settle(&mut self) {
        loop {
            let mut moved = false;
            loop {
                let lite = &mut *self.lite;
                let (a, d) = measure(|| crate::lite_action(lite));
                self.note(5, d);
                let Some(a) = a else { break };
                moved = true;
                match a {
                    MacAction::Transmit { frame, .. } => {
                        if self.reaches() {
                            self.coord.on_radio_frame(&frame, Self::meta(self.coord_channel));
                        }
                        let lite = &mut *self.lite;
                        let ((), d) = measure(|| {
                            crate::lite_tx_done(
                                lite,
                                TxResult {
                                    acked: false,
                                    frame_pending: false,
                                    timestamp_us: None,
                                },
                            );
                        });
                        self.note(4, d);
                    }
                    MacAction::SetChannel { channel, .. } => self.lite_channel = Some(channel),
                    MacAction::EnergyDetect { .. } => self.lite.on_energy_result(0),
                    _ => {}
                }
            }
            while let Some(a) = self.coord.next_radio_action() {
                moved = true;
                match a {
                    MacAction::Transmit { frame, .. } => {
                        if self.reaches() {
                            let lite = &mut *self.lite;
                            let meta = Self::meta(self.lite_channel);
                            let ((), d) = measure(|| crate::lite_rx(lite, &frame, meta));
                            self.note(3, d);
                        }
                        self.coord.on_tx_complete(Ok(TxResult {
                            acked: false,
                            frame_pending: false,
                            timestamp_us: None,
                        }));
                    }
                    MacAction::SetChannel { channel, .. } => self.coord_channel = Some(channel),
                    MacAction::EnergyDetect { .. } => self.coord.on_energy_result(0),
                    _ => {}
                }
            }
            while self.coord.next_event().is_some() {
                moved = true;
            }
            let lite = &mut *self.lite;
            let (n, d) = measure(|| crate::lite_events(lite));
            self.note(8, d);
            moved |= n > 0;
            if !moved {
                break;
            }
        }
    }

    /// Advances time to the next deadline (at most 250 ms) and polls.
    fn step(&mut self) {
        self.settle();
        let next = [self.coord.next_deadline(), self.lite.next_deadline()]
            .into_iter()
            .flatten()
            .map(|t| t.as_millis())
            .min()
            .unwrap_or(u64::MAX);
        self.now = next.clamp(self.now + 1, self.now + 250);
        let now = Instant::from_millis(self.now);
        self.coord.poll(now);
        let lite = &mut *self.lite;
        let ((), d) = measure(|| crate::lite_poll(lite, now));
        self.note(6, d);
        self.settle();
    }

    fn run_until(&mut self, ms: u64, f: impl Fn(&World) -> bool) -> bool {
        let end = self.now + ms;
        while self.now < end {
            if f(self) {
                return true;
            }
            self.step();
        }
        f(self)
    }
}

fn coordinator() -> &'static mut Coord {
    let mut cfg = StackConfig::new(LogicalDeviceType::Coordinator, ExtendedAddress(COORD));
    cfg.trust_center_policy.allow_joins = true;
    #[cfg(feature = "dlk")]
    {
        cfg.trust_center_policy.install_codes =
            panweave_security::trust_center::InstallCodePolicy::OptionalWithAnonymousNegotiation;
    }
    // SAFETY: built once, before any other access.
    let slot = unsafe { &mut *(&raw mut COORDINATOR) };
    let c = slot.write(Coord::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(1),
        MemoryStorage::new(),
    ));
    let _ = c.add_endpoint_with(Endpoint(1), ProfileId::HOME_AUTOMATION, |ep| {
        ep.add_instance(ias_zone::client()).ok()?;
        ep.add_instance(power_configuration::client()).ok()?;
        SimpleDescriptor::new(
            Endpoint(1),
            ProfileId::HOME_AUTOMATION,
            DeviceId(0x0400),
            0,
            &[panweave_types::ClusterId(0)],
            &[ias_zone::ID, power_configuration::ID],
        )
    });
    c
}

fn storage() -> NorFlashStore<RamFlash> {
    // SAFETY: the emulated flash is handed out once per (re)start; the
    // previous store was dropped with the device it belonged to.
    let flash = unsafe { &mut *(&raw mut FLASH) };
    match NorFlashStore::new(RamFlash(flash), 0, STORE_LEN) {
        Ok(s) => s,
        Err(_) => crate::halt(),
    }
}

pub fn run() -> ! {
    let coord = coordinator();
    let _ = coord.form_network_with_key(Key128::from_bytes([0x5A; 16]));
    // SAFETY: main runs once; the slot is (re)written only by lite_build.
    let slot = unsafe { &mut *(&raw mut DEVICE) };
    let (lite, construction) = measure(|| crate::lite_build(slot, SENSOR, storage()));
    let mut w = World {
        coord,
        lite,
        now: 1000,
        coord_channel: None,
        lite_channel: None,
        link: true,
        peaks: Peaks::default(),
        phase: 0,
    };
    w.note(0, construction);
    let formed = w.run_until(30_000, |w| w.coord.is_operating());
    let _ = w.coord.permit_join_network(254);
    w.phase = 1;
    let lite = &mut *w.lite;
    let ((), d) = measure(|| crate::lite_initialize(lite, Inputs::default()));
    w.note(1, d);
    w.phase = 2;
    let lite = &mut *w.lite;
    let ((), d) = measure(|| crate::lite_commission(lite));
    w.note(2, d);
    let joined = w.run_until(120_000, |w| w.lite.stack.is_operating());
    w.run_until(15_000, |_| false);
    // Enrolled by hand with the coordinator as CIE (the coordinator
    // runs no IAS CIE logic).
    if let Some(c) = w
        .lite
        .stack
        .zcl
        .cluster_mut(SENSOR_ENDPOINT, ias_zone::ID, Role::Server)
    {
        ias_zone::restore_enrollment(
            c,
            &ias_zone::Enrollment {
                cie_address: ExtendedAddress(COORD),
                cie: (panweave_types::ShortAddress(0), Endpoint(1)),
                zone_id: Some(1),
            },
        );
    }
    w.phase = 3;
    let lite = &mut *w.lite;
    let ((), d) = measure(|| {
        crate::lite_inputs(
            lite,
            Inputs {
                alarm: true,
                ..Inputs::default()
            },
        );
    });
    w.note(7, d);
    let reported = w.run_until(30_000, |w| w.lite.delivery() == Delivery::Confirmed);
    w.phase = 4;
    w.link = false;
    w.run_until(60_000, |_| false);
    w.link = true;
    let rejoined = w.run_until(240_000, |w| {
        w.lite.stack.is_operating() && w.lite.delivery() == Delivery::Confirmed
    });
    w.phase = 5;
    // Power loss: a new device over the same flash.
    let slot = unsafe { &mut *(&raw mut DEVICE) };
    // SAFETY: the old device is not used again; its store is replaced.
    unsafe { slot.assume_init_drop() };
    let (lite, d) = measure(|| crate::lite_build(slot, SENSOR, storage()));
    w.lite = lite;
    w.note(0, d);
    let lite = &mut *w.lite;
    let ((), d) = measure(|| crate::lite_initialize(lite, Inputs::default()));
    w.note(1, d);
    let restarted = w.run_until(240_000, |w| w.lite.stack.is_operating());

    hprintln!("PANWEAVE-LITE-QEMU");
    hprintln!(
        "result formed={} joined={} reported={} rejoined={} restarted={}",
        formed,
        joined,
        reported,
        rejoined,
        restarted
    );
    hprintln!("dlk {}", cfg!(feature = "dlk"));
    for (name, v) in PHASES.iter().zip(w.peaks.phase) {
        hprintln!("phase {} {}", v, name);
    }
    for (name, v) in ENTRIES.iter().zip(w.peaks.entry) {
        hprintln!("entry {} {}", v, name);
    }
    hprintln!(
        "dropped device={} stack={} zcl={} zdo={} aps_actions={} aps_events={}",
        w.lite.dropped_events,
        w.lite.stack.dropped_events,
        w.lite.stack.zcl.dropped,
        w.lite.stack.zdo.dropped,
        w.lite.stack.aps.stats.actions_dropped,
        w.lite.stack.aps.stats.events_dropped
    );
    hprintln!("virtual_ms {}", w.now);
    debug::exit(if formed && joined && reported && rejoined && restarted {
        debug::EXIT_SUCCESS
    } else {
        debug::EXIT_FAILURE
    });
    crate::halt()
}
