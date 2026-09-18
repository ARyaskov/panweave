//! A Zigbee 4.0 On/Off Light Switch on the ESP32-C6 Super Mini.
//!
//! An rx-on end device (USB-powered: it does not sleep) whose BOOT
//! button is the switch. Factory new, it steers into an open network.
//! The first press on the network runs finding & binding as the
//! initiator: the light (or coordinator) must be identifying — press
//! its button first — and a binding for On/Off is created. Every later
//! press sends Toggle through the binding. Holding BOOT for three
//! seconds factory-resets the switch.
//!
//! The LED blinks once per transmitted Toggle.
//!
//! Flash and watch: `cargo run --release --bin switch`.

#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_println::println;
use panweave::aps::Destination;
use panweave::runtime::StackEvent;
use panweave::security::cipher::SoftwareAes;
use panweave::types::{Endpoint, ProfileId};
use panweave::zcl::clusters::on_off;
use panweave::zcl::frame::Direction;
use panweave::{EndDevice, Event, endpoints};
use panweave_esp32c6::{Board, Runner, now};

esp_bootloader_esp_idf::esp_app_desc!();

const SWITCH: Endpoint = Endpoint(1);

#[esp_hal::main]
fn main() -> ! {
    let mut board = Board::init();
    println!("panweave on/off switch, IEEE {:?}", board.ieee);
    let mut node = EndDevice::new(board.ieee)
        .identity(b"panweave", b"esp32c6-switch")
        .build::<SoftwareAes, _, _>(board.rng, board.storage);
    let (descriptor, endpoint) = endpoints::on_off_light_switch(SWITCH).expect("switch endpoint");
    node.add_endpoint(descriptor, endpoint).expect("endpoint");
    let mut runner = Runner::new(board.radio);

    match node.initialize() {
        Ok(panweave::runtime::Restored::OnNetwork) => println!("rejoining the network"),
        Ok(_) => {
            println!("factory new: steering");
            let _ = node.steer();
        }
        Err(e) => println!("storage: {e:?}"),
    }

    let mut pressed_at: Option<u64> = None;
    let mut bound = false;
    let mut led_off_at: Option<u64> = None;
    loop {
        let deadline = runner.step(&mut node);
        while let Some(event) = node.next_event() {
            match event {
                Event::Stack(StackEvent::Joined {
                    short,
                    pan_id,
                    rejoin,
                }) => {
                    println!(
                        "joined PAN {:#06x} as {:#06x} (rejoin: {rejoin})",
                        pan_id.0, short.0
                    );
                    bound = !node.stack.aps.bindings.is_empty();
                }
                Event::Stack(StackEvent::Left { .. }) => {
                    println!("left the network");
                    bound = false;
                }
                Event::Commissioning(outcome) => {
                    println!("commissioning: {outcome:?}");
                    bound = !node.stack.aps.bindings.is_empty();
                }
                Event::Stack(other) => println!("{other:?}"),
            }
        }
        let pressed = board.button.is_low();
        match (pressed, pressed_at) {
            (true, None) => pressed_at = Some(now().as_millis()),
            (true, Some(t)) if now().as_millis() - t >= 3000 => {
                println!("factory reset");
                let _ = node.factory_reset();
                bound = false;
                pressed_at = Some(u64::MAX / 2);
            }
            (false, Some(t)) => {
                pressed_at = None;
                if now().as_millis().saturating_sub(t) < 3000 {
                    if !node.stack.is_operating() {
                        println!("steering");
                        let _ = node.steer();
                    } else if !bound {
                        println!("finding & binding: looking for an identifying light");
                        let _ = node.find_and_bind_initiator(SWITCH, None, &[on_off::ID]);
                    } else {
                        println!("toggle");
                        let sent = node.stack.zcl.send_command(
                            Destination::Bound,
                            ProfileId::HOME_AUTOMATION,
                            on_off::ID,
                            SWITCH,
                            on_off::CMD_TOGGLE,
                            Direction::ToServer,
                            None,
                            &[],
                        );
                        if let Err(e) = sent {
                            println!("toggle not sent: {e:?}");
                        }
                        node.stack.flush();
                        board.led.set_high();
                        led_off_at = Some(now().as_millis() + 100);
                    }
                }
            }
            _ => {}
        }
        if led_off_at.is_some_and(|t| now().as_millis() >= t) {
            led_off_at = None;
            board.led.set_low();
        }
        runner.idle_until(deadline, || board.button.is_low() != pressed);
    }
}
