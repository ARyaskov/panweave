//! A standalone Zigbee hub on the ESP32-C6 Super Mini: coordinator and
//! Trust Center of its own network, device registry, interviews, IAS Zone
//! sensors and lights, controlled by a host over USB with the Panweave
//! Hub Protocol (`panweave-hub-cli`, or any application built on the
//! `panweave-hub` crate).
//!
//! * First boot: forms a network (channel 11, see `docs/esp32c6.md`).
//!   Later boots resume it, and the registry, from flash.
//! * The network is closed. A host opens it (`PermitJoin`, at most
//!   254 s), or a short press of BOOT opens it for 180 s; the LED is on
//!   while it is open.
//! * Joining devices are interviewed and configured automatically; their
//!   events go to the host when one is connected, and the network keeps
//!   running when none is.
//! * Holding BOOT for ten seconds factory-resets the hub: the network and
//!   the registry are erased and a new network is formed — every device
//!   has to join again.
//!
//! Flash with the hub's partition table, which adds the registry
//! partition: see `docs/esp32c6-hub.md`. Without it the hub runs with a
//! RAM-only registry and says so in `GetHubInfo`.

#![no_std]
#![no_main]

use esp_backtrace as _;
use panweave::runtime::Restored;
use panweave::security::cipher::SoftwareAes;
use panweave::types::Endpoint;
use panweave::types::time::Instant;
use panweave::{Coordinator, Event, endpoints};
use panweave_esp32c6::hub::{HubStore, UsbLink, Watchdog};
use panweave_esp32c6::{Board, Runner, now};
use panweave_hub::{Access, Hub, HubConfig, PlatformCounters, Session, hub_endpoint};

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
const WATCHDOG_SECONDS: u64 = 10;
/// Longest idle wait while output is queued or events are waiting.
const BUSY_IDLE_MS: u64 = 5;

fn earliest(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if x.as_millis() <= y.as_millis() { x } else { y }),
        (x, y) => x.or(y),
    }
}

#[esp_hal::main]
fn main() -> ! {
    let (mut board, hub_flash) = Board::init_hub();
    let mut watchdog = Watchdog::start(board.rtc_timer, WATCHDOG_SECONDS);
    let persistent = hub_flash.is_some();
    let store = hub_flash.map_or(HubStore::None, HubStore::Flash);

    let mut node = Coordinator::new(board.ieee)
        .identity(b"panweave", b"esp32c6-hub")
        .build::<SoftwareAes, _, _>(board.rng, board.storage);
    // Pre-Zigbee-3.0 devices never request a unique Trust Center link
    // key; BDB 3.1 has the Trust Center remove them. Opt-in only.
    if cfg!(feature = "legacy-joiners") {
        node.stack.config.trust_center_policy.require_key_exchange = false;
    }
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
    // A registry that cannot be read is reported to the host as a hub
    // error; the network still starts.
    let _ = hub.restore();

    // USB is a local, physical connection: full access (see the trust
    // boundary in docs/esp32c6-hub.md).
    let mut session: Session = Session::new(Access::Admin);
    let mut usb = UsbLink::new(board.usb);
    let mut runner = Runner::new(board.radio);

    match node.initialize() {
        Ok(Restored::OnNetwork) => hub.network_restored(&node.stack),
        Ok(_) | Err(_) => {
            let _ = node.form_network();
        }
    }

    let mut pressed_at: Option<u64> = None;
    loop {
        watchdog.feed();
        let deadline = runner.step(&mut node);
        while let Some(event) = node.next_event() {
            if let Event::Stack(e) = event {
                hub.on_stack_event(&mut node.stack, &e);
            }
        }
        hub.poll(&mut node.stack);
        hub.platform = PlatformCounters {
            radio_rx: runner.rx_frames,
            radio_tx: runner.tx_frames,
            radio_dropped: runner.radio.dropped,
            stack_events_dropped: node
                .dropped_events
                .saturating_add(node.stack.dropped_events),
        };

        // The host: requests in, responses and events out.
        usb.receive(|bytes| {
            session.receive(bytes, &mut hub, &mut node.stack);
        });
        session.pump_events(&mut hub);
        usb.transmit(&mut session, now().as_millis());

        // BOOT: a short press opens the network, a long hold resets.
        let pressed = board.button.is_low();
        match (pressed, pressed_at) {
            (true, None) => pressed_at = Some(now().as_millis()),
            (true, Some(t)) if now().as_millis().saturating_sub(t) >= FACTORY_RESET_MS => {
                let _ = node.factory_reset();
                let _ = hub.factory_reset();
                hub.attach(&mut node.stack);
                let _ = node.form_network();
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
