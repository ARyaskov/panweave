//! A Zigbee 4.0 coordinator (Trust Center) on the ESP32-C6 Super Mini.
//!
//! On the first boot it forms a centralized network on the first
//! primary channel (energy detection is not available, see
//! `Radio::energy_detect`); afterwards it resumes the network from
//! flash. A short press of BOOT opens the network for 180 s and makes
//! the coordinator's endpoint a finding & binding target — a switch or a
//! sensor that then runs the initiator side binds to it. Everything the
//! network says (joins, announcements, reports, commands) goes to the
//! serial console; attribute reports are decoded. Holding BOOT for three
//! seconds factory-resets the coordinator (the network is gone for
//! every device on it).
//!
//! The LED is on while the network is open.
//!
//! Flash and watch: `cargo run --release --bin coordinator`.

#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_println::println;
use panweave::codec::{Decode, Reader};
use panweave::runtime::StackEvent;
use panweave::security::cipher::SoftwareAes;
use panweave::types::Endpoint;
use panweave::zcl::global::AttributeValue;
use panweave::{Coordinator, Event, endpoints};
use panweave_esp32c6::{Board, Runner, now};

esp_bootloader_esp_idf::esp_app_desc!();

/// The coordinator's application endpoint: an On/Off Light (a target
/// with an On/Off server for switches) whose light is the LED.
const EP: Endpoint = Endpoint(1);
const OPEN_SECONDS: u64 = 180;

#[esp_hal::main]
fn main() -> ! {
    let mut board = Board::init();
    println!("panweave coordinator, IEEE {:?}", board.ieee);
    let mut node = Coordinator::new(board.ieee)
        .identity(b"panweave", b"esp32c6-coordinator")
        .build::<SoftwareAes, _, _>(board.rng, board.storage);
    // Any device may join while the network is open; production
    // deployments restrict this (`TrustCenterPolicy`, install codes).
    node.stack.config.trust_center_policy.allow_joins = true;
    let (descriptor, endpoint) = endpoints::on_off_light(EP).expect("endpoint");
    node.add_endpoint(descriptor, endpoint).expect("endpoint");
    let mut runner = Runner::new(board.radio);

    match node.initialize() {
        Ok(panweave::runtime::Restored::OnNetwork) => println!("resuming the network"),
        Ok(_) => {
            println!("factory new: forming a network");
            let _ = node.form_network();
        }
        Err(e) => println!("storage: {e:?}"),
    }

    let mut pressed_at: Option<u64> = None;
    let mut open_until: Option<u64> = None;
    loop {
        let deadline = runner.step(&mut node);
        while let Some(event) = node.next_event() {
            match event {
                Event::Stack(StackEvent::NetworkFormed {
                    pan_id,
                    extended_pan_id,
                }) => {
                    println!(
                        "network formed: PAN {:#06x}, extended PAN {:#018x}, channel {}",
                        pan_id.0,
                        extended_pan_id.0,
                        runner.radio.channel()
                    );
                }
                Event::Stack(StackEvent::DeviceAuthorized { ieee, short }) => {
                    println!("device {:#018x} joined as {:#06x}", ieee.0, short.0);
                }
                Event::Stack(StackEvent::DeviceAnnounce { ieee, short, .. }) => {
                    println!("announce: {:#018x} is {:#06x}", ieee.0, short.0);
                }
                Event::Stack(StackEvent::DeviceLeft { .. }) => println!("a device left"),
                Event::Stack(StackEvent::ZclReport(frame)) => {
                    let o = &frame.origin;
                    let mut r = Reader::new(&frame.payload);
                    while let Ok(rec) = AttributeValue::decode(&mut r) {
                        println!(
                            "report from {:#06x}/{} cluster {:#06x}: attribute {:#06x} = {:?}",
                            o.src.0, o.src_endpoint.0, o.cluster.0, rec.id.0, rec.value
                        );
                    }
                }
                Event::Stack(StackEvent::ZclCommand(frame)) => {
                    let o = &frame.origin;
                    println!(
                        "command {:#04x} from {:#06x}/{} cluster {:#06x}",
                        o.header.command.0, o.src.0, o.src_endpoint.0, o.cluster.0
                    );
                }
                Event::Stack(StackEvent::OnOff { on, .. }) => {
                    println!("light {}", if on { "on" } else { "off" });
                    if open_until.is_none() {
                        board.led.set_level(on.into());
                    }
                }
                Event::Commissioning(outcome) => println!("commissioning: {outcome:?}"),
                Event::Stack(other) => println!("{other:?}"),
            }
        }
        // The button: press to open the network, hold to reset.
        let pressed = board.button.is_low();
        match (pressed, pressed_at) {
            (true, None) => pressed_at = Some(now().as_millis()),
            (true, Some(t)) if now().as_millis() - t >= 3000 => {
                println!("factory reset");
                let _ = node.factory_reset();
                pressed_at = Some(u64::MAX / 2);
            }
            (false, Some(t)) => {
                pressed_at = None;
                if now().as_millis().saturating_sub(t) < 3000 {
                    println!("network open for {OPEN_SECONDS} s, finding & binding target");
                    let _ = node.open_network();
                    let _ = node.find_and_bind_target(EP);
                    open_until = Some(now().as_millis() + OPEN_SECONDS * 1000);
                    board.led.set_high();
                }
            }
            _ => {}
        }
        if open_until.is_some_and(|t| now().as_millis() >= t) {
            open_until = None;
            board.led.set_low();
            println!("network closed");
        }
        runner.idle_until(deadline, || board.button.is_low() != pressed);
    }
}
