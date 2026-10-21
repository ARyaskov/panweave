//! A standalone Zigbee hub on the ESP32-C6 Super Mini: coordinator and
//! Trust Center of its own network, device registry, interviews, IAS Zone
//! sensors and lights, controlled by a host over USB with the Panweave
//! Hub Protocol (`panweave-hub-cli`, or any application built on the
//! `panweave-hub` crate).
//!
//! * First boot: forms a network (channel 11, see `docs/esp32c6.md`).
//!   Later boots resume it, and the registry, from flash. When the
//!   stack's storage cannot be read, or holds corrupt records and no
//!   network, the hub does **not** form a new network on its own: it
//!   reports the problem (boot report, trace) and waits for a factory
//!   reset (BOOT held ten seconds).
//! * The network is closed. A host opens it (`PermitJoin`, at most
//!   254 s), or a short press of BOOT opens it for 180 s; the LED is on
//!   while it is open.
//! * Joining devices are interviewed and configured automatically; their
//!   events go to the host when one is connected, and the network keeps
//!   running when none is.
//! * Holding BOOT for ten seconds factory-resets the hub: the network and
//!   the registry are erased and a new network is formed — every device
//!   has to join again.
//! * Diagnostics: a boot report, a trace of typed records, counters and,
//!   when an Admin host starts one, a bounded capture of radio frames —
//!   all through the protocol; the hub never prints text on its port
//!   (`docs/esp32c6-diagnostics.md`).
//!
//! Flash with the hub's partition table, which adds the registry
//! partition: see `docs/esp32c6-hub.md`. Without it the hub runs with a
//! RAM-only registry and says so.

#![no_std]
#![no_main]

use esp_backtrace as _;
use panweave::security::cipher::SoftwareAes;
use panweave::types::Endpoint;
use panweave::types::time::Instant;
use panweave::{Coordinator, Event, endpoints};
use panweave_esp32c6::hub::{HubStore, UsbLink, Watchdog, store_usage};
use panweave_esp32c6::memory::{self, StackMonitor};
use panweave_esp32c6::{Board, Runner, Traffic, now};
use panweave_hub::boot::{RestoreRetry, RetryOutcome, stored_network};
use panweave_hub::capture::flags;
use panweave_hub::diag::{Category, DiagRecord, Severity, code};
use panweave_hub::protocol::ResetKind;
use panweave_hub::protocol::{BootReport, NetworkRestore, PartitionEntry, PartitionFinding};
use panweave_hub::supervisor::{HealthSupervisor, Observation, Supervision};
use panweave_hub::{Access, Hub, HubConfig, Session, esp32c6, hub_endpoint, partitions};

esp_bootloader_esp_idf::esp_app_desc!();

/// The hub's application endpoint.
const HUB_EP: Endpoint = Endpoint(1);
/// The Trust Center utility endpoint (Keep-Alive server, BDB 3.1 §6.4).
const UTILITY_EP: Endpoint = Endpoint(2);
/// Permit-join window opened by the BOOT button.
const BUTTON_OPEN_SECONDS: u8 = 180;
/// BOOT held this long factory-resets the hub.
const FACTORY_RESET_MS: u64 = 10_000;
/// Watchdog timeout.
const WATCHDOG_SECONDS: u16 = 10;
/// Longest idle wait while output is queued or events are waiting.
const BUSY_IDLE_MS: u64 = 5;
/// A loop turn longer than this (without the idle wait) is an overrun.
const OVERRUN_US: u64 = 50_000;
/// Attempts at reading the stack's storage at boot.
const RESTORE_ATTEMPTS: u32 = 3;
/// A loop turn longer than this may outlast a sleepy child's receive
/// window after its data request (`macMaxFrameTotalWaitTime`, about
/// 20 ms at 2.4 GHz).
const INDIRECT_WINDOW_US: u64 = 20_000;
/// How often the stack watermark is scanned.
const STACK_SCAN_MS: u64 = 10_000;

fn earliest(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if x.as_millis() <= y.as_millis() { x } else { y }),
        (x, y) => x.or(y),
    }
}

#[esp_hal::main]
fn main() -> ! {
    // First: paint the free stack for the watermark (src/memory.rs).
    let stack_monitor = StackMonitor::paint();
    let (mut board, hub_flash, scan) = Board::init_hub();
    let mut watchdog = Watchdog::start(board.rtc_timer, u64::from(WATCHDOG_SECONDS));
    let reset_raw = esp_hal::rtc_cntl::reset_reason(esp_hal::system::Cpu::ProCpu).map(|r| r as u8);
    let persistent = hub_flash.is_some();
    let store = hub_flash.map_or(HubStore::None, HubStore::Flash);

    let mut node = Coordinator::new(board.ieee)
        .identity(b"panweave", b"esp32c6-hub")
        .build::<SoftwareAes, _, _>(board.rng, board.storage);
    let (descriptor, endpoint) = hub_endpoint(HUB_EP).expect("hub endpoint");
    node.add_endpoint(descriptor, endpoint)
        .expect("hub endpoint");
    if let Some((descriptor, endpoint)) = endpoints::trust_center_utility(UTILITY_EP) {
        let _ = node.add_endpoint(descriptor, endpoint);
    }

    let mut hub = Hub::new(
        HubConfig {
            endpoint: HUB_EP,
            firmware: env!("CARGO_PKG_VERSION"),
            persistent,
            ..HubConfig::default()
        },
        store,
    );
    hub.attach(&mut node.stack);
    hub.log(
        DiagRecord::new(Category::Watchdog, Severity::Info, code::WATCHDOG_ARMED)
            .arg(u32::from(WATCHDOG_SECONDS)),
    );

    // The partition table actually flashed, checked without touching it.
    let findings = if scan.read {
        partitions::validate(&scan.table, scan.flash_size, None)
    } else {
        heapless::Vec::new()
    };
    for f in &findings {
        let severity = if f.is_fatal() {
            Severity::Error
        } else {
            Severity::Warning
        };
        hub.log(
            DiagRecord::new(Category::Boot, severity, code::PARTITION_PROBLEM)
                .status(f.code())
                .arg(u32::from(f.partition().unwrap_or(0xff))),
        );
    }
    // A registry that cannot be read is reported; the network still
    // starts.
    let registry = hub.restore().ok();

    // The USB link: a local, physical connection with full access (the
    // trust boundary is documented in docs/esp32c6-hub.md).
    let mut session: Session = Session::new(Access::Admin);
    let mut usb = UsbLink::new(board.usb);
    let mut runner = Runner::new(board.radio);

    // Never replace an existing network behind the user's back: form one
    // only when the storage was read and genuinely holds none.
    let mut restored = node.initialize();
    for _ in 1..RESTORE_ATTEMPTS {
        if restored.is_ok() {
            break;
        }
        restored = node.initialize();
    }
    if let Err(e) = restored {
        hub.storage_error(e);
    }
    let detail = node.stack.restore_detail();
    let outcome = NetworkRestore::decide(
        stored_network(restored, detail),
        node.stack.storage.stats.corrupt_records,
    );
    match outcome {
        NetworkRestore::Restored => hub.network_restored(&node.stack),
        NetworkRestore::Formed => {
            let _ = node.form_network();
        }
        NetworkRestore::StoredUnusable => hub.log(
            DiagRecord::new(
                Category::Persistence,
                Severity::Critical,
                code::NETWORK_RECORD_UNUSABLE,
            )
            .status(detail.code()),
        ),
        _ => {}
    }
    hub.set_network_restore(outcome);
    // An unreadable storage is read again, with a growing interval; a
    // network is never formed on that path.
    let mut retry = RestoreRetry::after_boot(outcome, now().as_millis());

    let mut report = BootReport {
        chip: heapless::Vec::from_slice(b"ESP32-C6").unwrap_or_default(),
        chip_revision: {
            let r = esp_hal::efuse::chip_revision();
            Some(u16::from(r.major) * 100 + u16::from(r.minor))
        },
        firmware: heapless::Vec::from_slice(env!("CARGO_PKG_VERSION").as_bytes())
            .unwrap_or_default(),
        build: {
            let id = option_env!("PANWEAVE_BUILD_ID")
                .unwrap_or("unknown")
                .as_bytes();
            heapless::Vec::from_slice(id.get(..id.len().min(24)).unwrap_or(&[])).unwrap_or_default()
        },
        reset: Some(esp32c6::classify_reset(reset_raw)),
        reset_raw,
        cpu_mhz: u16::try_from(esp_hal::clock::cpu_clock().as_mhz()).ok(),
        flash_size: Some(scan.flash_size),
        partition_table_read: scan.read,
        hubdata: scan.hubdata,
        ieee: board.ieee.0,
        radio_channel: Some(runner.radio.channel()),
        network: Some(outcome),
        registry_devices: registry.map(|n| u8::try_from(n).unwrap_or(u8::MAX)),
        registry_persistent: persistent,
        usb_ready: true,
        watchdog_s: Some(WATCHDOG_SECONDS),
        ..BootReport::default()
    };
    for p in &scan.table {
        let _ = report.partitions.push(PartitionEntry {
            label: heapless::Vec::from_slice(p.label.as_bytes()).unwrap_or_default(),
            kind: p.kind,
            subtype: p.subtype,
            offset: p.offset,
            size: p.size,
        });
    }
    for f in &findings {
        let _ = report.findings.push(PartitionFinding {
            code: f.code(),
            partition: f.partition().unwrap_or(0xff),
        });
    }
    let boot_ms = u32::try_from(now().as_millis()).unwrap_or(u32::MAX);
    report.boot_ms = Some(boot_ms);
    hub.set_boot_report(report);
    hub.log(DiagRecord::new(Category::Boot, Severity::Info, code::BOOT_COMPLETED).arg(boot_ms));

    let mut pressed_at: Option<u64> = None;
    let mut iterations: u32 = 0;
    let mut loop_max_us: u32 = 0;
    let mut overruns: u32 = 0;
    let mut over_window: u32 = 0;
    let mut hub_poll_max_us: u32 = 0;
    // A boot that followed a watchdog reset never escalates a stall to
    // another reset (panweave_hub::supervisor): no reset loops.
    let mut supervisor = HealthSupervisor::new(
        now().as_millis(),
        esp32c6::classify_reset(reset_raw) == ResetKind::WatchdogReset,
    );
    let mut stack_peak = stack_monitor.peak();
    let mut next_stack_scan = now().as_millis() + STACK_SCAN_MS;
    watchdog.feed();
    loop {
        let turn = esp_hal::time::Instant::now();
        let deadline = runner.step_observed(&mut node, |t, channel| {
            if !hub.capture_active() {
                return;
            }
            let at = now().as_millis();
            match t {
                Traffic::Tx {
                    frame,
                    ack_requested,
                    acked,
                    fault,
                } => {
                    let mut f = 0;
                    if ack_requested {
                        f |= if acked { flags::ACKED } else { flags::NO_ACK };
                    }
                    if fault {
                        f |= flags::TX_FAULT;
                    }
                    hub.capture_frame(at, channel, frame, f, None, None);
                }
                Traffic::Rx { frame, rssi, lqi } => {
                    hub.capture_frame(at, channel, frame, flags::RX, Some(rssi), Some(lqi));
                }
            }
        });
        while let Some(event) = node.next_event() {
            if let Event::Stack(e) = event {
                hub.on_stack_event(&mut node.stack, &e);
            }
        }
        hub.platform.radio_rx = runner.rx_frames;
        hub.platform.radio_tx = runner.tx_frames;
        hub.platform.radio_dropped = runner.radio.dropped;
        hub.platform.stack_events_dropped = node
            .dropped_events
            .saturating_add(node.stack.dropped_events);
        hub.platform.driver = Some(runner.radio.stats);
        hub.platform.tx_power_dbm = Some(runner.radio.tx_power());
        hub.platform.energy_detection = false;
        hub.platform.loop_iterations = Some(iterations);
        hub.platform.loop_max_us = Some(loop_max_us);
        hub.platform.loop_overruns = Some(overruns);
        hub.platform.radio_step_max_us = Some(runner.step_max_us);
        hub.platform.watchdog_s = Some(WATCHDOG_SECONDS);
        hub.platform.usb_rx_bytes = Some(usb.rx_bytes);
        hub.platform.usb_tx_bytes = Some(usb.tx_bytes);
        hub.platform.stack_store = Some(store_usage(&node.stack.storage));
        hub.platform.hub_store = match hub.storage() {
            HubStore::Flash(s) => Some(store_usage(s)),
            HubStore::None => None,
        };
        if now().as_millis() >= next_stack_scan {
            stack_peak = stack_monitor.peak();
            next_stack_scan = now().as_millis() + STACK_SCAN_MS;
        }
        let (heap_size, heap_used, heap_peak) = memory::heap();
        let t = &mut hub.platform.target;
        t.stack_size = Some(stack_monitor.size());
        t.stack_peak = Some(stack_peak);
        t.heap_size = Some(heap_size);
        t.heap_used = Some(heap_used);
        t.heap_peak = Some(heap_peak);
        t.loop_over_20ms = Some(over_window);
        t.hub_poll_max_us = Some(hub_poll_max_us);
        t.radio_idle_ms =
            Some(u32::try_from(supervisor.radio_idle_ms(now().as_millis())).unwrap_or(u32::MAX));
        t.rx_bursts_cut = Some(runner.rx_bursts_cut);
        t.health = Some(supervisor.health(now().as_millis()).code());
        t.radio_recoveries = Some(runner.radio.recoveries);
        let poll_started = esp_hal::time::Instant::now();
        hub.poll(&mut node.stack);
        hub_poll_max_us = hub_poll_max_us
            .max(u32::try_from(poll_started.elapsed().as_micros()).unwrap_or(u32::MAX));

        // A boot that could not read the stack's storage tries again.
        if retry.due(now().as_millis()) {
            let r = node.initialize();
            if let Err(e) = r {
                hub.storage_error(e);
            }
            let stored = stored_network(r, node.stack.restore_detail());
            let result = retry.on_attempt(now().as_millis(), stored);
            let status = match result {
                RetryOutcome::Retrying => 0,
                RetryOutcome::Restored => 1,
                RetryOutcome::GaveUp(_) => 2,
            };
            hub.log(
                DiagRecord::new(
                    Category::Persistence,
                    Severity::Warning,
                    code::NETWORK_RESTORE_RETRY,
                )
                .status(status)
                .arg(retry.attempts()),
            );
            match result {
                RetryOutcome::Restored => {
                    hub.network_restored(&node.stack);
                    hub.set_network_restore(NetworkRestore::Restored);
                }
                RetryOutcome::GaveUp(o) => hub.set_network_restore(o),
                RetryOutcome::Retrying => {}
            }
        }

        // The host: requests in, responses and events out.
        usb.receive(|bytes| {
            session.receive(bytes, &mut hub, &mut node.stack);
        });
        session.pump_events(&mut hub);
        let dropped = usb.transmit(&mut session, now().as_millis());
        if dropped > 0 {
            hub.log(
                DiagRecord::new(Category::Usb, Severity::Warning, code::USB_OUTPUT_DISCARDED)
                    .arg(u32::try_from(dropped).unwrap_or(u32::MAX)),
            );
        }

        // BOOT: a short press opens the network, a long hold resets.
        let pressed = board.button.is_low();
        match (pressed, pressed_at) {
            (true, None) => pressed_at = Some(now().as_millis()),
            (true, Some(t)) if now().as_millis().saturating_sub(t) >= FACTORY_RESET_MS => {
                let _ = node.factory_reset();
                let _ = hub.factory_reset();
                hub.attach(&mut node.stack);
                let _ = node.form_network();
                hub.set_network_restore(NetworkRestore::Formed);
                retry = RestoreRetry::after_boot(NetworkRestore::Formed, now().as_millis());
                // Until released: no second reset.
                pressed_at = Some(u64::MAX / 2);
            }
            (false, Some(t)) => {
                pressed_at = None;
                if now().as_millis().saturating_sub(t) < FACTORY_RESET_MS {
                    let _ = hub.permit_join(&mut node.stack, BUTTON_OPEN_SECONDS);
                }
            }
            _ => {}
        }
        board
            .led
            .set_level((hub.permit_join_remaining() > 0 || pressed).into());

        iterations = iterations.wrapping_add(1);
        let busy = turn.elapsed().as_micros();
        loop_max_us = loop_max_us.max(u32::try_from(busy).unwrap_or(u32::MAX));
        if busy > INDIRECT_WINDOW_US {
            over_window = over_window.wrapping_add(1);
        }
        if busy > OVERRUN_US {
            overruns = overruns.wrapping_add(1);
            hub.log(
                DiagRecord::new(Category::Resources, Severity::Warning, code::LOOP_OVERRUN)
                    .arg(u32::try_from(busy).unwrap_or(u32::MAX)),
            );
        }

        // Watchdog: fed every turn the loop runs, unless the supervisor
        // has evidence of a stall that its recovery did not fix
        // (panweave_hub::supervisor). Silence is never such evidence.
        let d = &runner.radio.stats;
        let observation = Observation {
            now_ms: now().as_millis(),
            tx_completed: d.tx_attempts.wrapping_sub(d.tx_faults),
            tx_unacknowledged: d.tx_no_ack.wrapping_add(d.tx_cca_failures),
            tx_faults: d.tx_faults,
            rx_frames: d.rx_frames,
            queue_full: node
                .stack
                .mac
                .stats
                .queue_limit_reached
                .wrapping_add(node.stack.nwk.stats.pending_full),
            stack_overdue: deadline.is_some_and(|t| t.as_millis() < now().as_millis()),
        };
        let idle = u32::try_from(supervisor.radio_idle_ms(now().as_millis())).unwrap_or(u32::MAX);
        match supervisor.observe(observation) {
            Supervision::Feed => watchdog.feed(),
            Supervision::Recover(cause) => {
                hub.log(
                    DiagRecord::new(Category::Watchdog, Severity::Error, code::STALL_SUSPECTED)
                        .status(cause.code())
                        .arg(idle),
                );
                runner.radio.recover();
                watchdog.feed();
            }
            Supervision::Escalate(cause) => {
                hub.log(
                    DiagRecord::new(
                        Category::Watchdog,
                        Severity::Critical,
                        code::STALL_CONFIRMED,
                    )
                    .status(cause.code())
                    .arg(1),
                );
                // The reason survives the reset; nothing else is written.
                let _ = hub.record_stall_reset(cause);
            }
            Supervision::ConfirmedNoEscalation(cause) => {
                hub.log(
                    DiagRecord::new(
                        Category::Watchdog,
                        Severity::Critical,
                        code::STALL_CONFIRMED,
                    )
                    .status(cause.code())
                    .arg(0),
                );
                watchdog.feed();
            }
            Supervision::Withhold => {}
        }

        let mut wake = earliest(deadline, hub.next_deadline());
        if session.tx_len() > 0 || hub.pending_events() > 0 {
            wake = earliest(
                wake,
                Some(Instant::from_millis(now().as_millis() + BUSY_IDLE_MS)),
            );
        }
        runner.idle_until(wake, || usb.fill() || board.button.is_low() != pressed);
    }
}
