//! A Zigbee 4.0 router On/Off Light on the ESP32-C6 Super Mini.
//!
//! The blue LED is the light. On power-up the node restores its network
//! from flash and resumes, or, factory-new, steers: it looks for an open
//! network and joins it (open one on the coordinator first). Holding
//! BOOT for three seconds factory-resets the node; a short press starts
//! steering again (or, on the network, opens it for other joiners and
//! makes this light a finding & binding target for 180 s).
//!
//! Flash and watch: `cargo run --release --bin on_off_light`.

#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_println::println;
use panweave::runtime::StackEvent;
use panweave::security::cipher::SoftwareAes;
use panweave::types::Endpoint;
use panweave::{Event, Router, endpoints};
use panweave_esp32c6::{Board, Runner, now};

esp_bootloader_esp_idf::esp_app_desc!();

const LIGHT: Endpoint = Endpoint(1);

#[esp_hal::main]
fn main() -> ! {
    let mut board = Board::init();
    println!("panweave on/off light, IEEE {:?}", board.ieee);
    let mut node = Router::new(board.ieee)
        .identity(b"panweave", b"esp32c6-light")
        .build::<SoftwareAes, _, _>(board.rng, board.storage);
    let (descriptor, endpoint) = endpoints::on_off_light(LIGHT).expect("light endpoint");
    node.add_endpoint(descriptor, endpoint).expect("endpoint");
    let mut runner = Runner::new(board.radio);

    match node.initialize() {
        Ok(panweave::runtime::Restored::OnNetwork) => println!("resuming on the network"),
        Ok(_) => {
            println!("factory new: steering");
            let _ = node.steer();
        }
        Err(e) => println!("storage: {e:?}"),
    }

    let mut pressed_at: Option<u64> = None;
    loop {
        let deadline = runner.step(&mut node);
        while let Some(event) = node.next_event() {
            match event {
                Event::Stack(StackEvent::OnOff { endpoint, on }) if endpoint == LIGHT => {
                    board.led.set_level(on.into());
                    println!("light {}", if on { "on" } else { "off" });
                }
                Event::Stack(StackEvent::Joined {
                    short,
                    pan_id,
                    rejoin,
                }) => {
                    println!("joined PAN {pan_id:?} as {short:?} (rejoin: {rejoin})");
                }
                Event::Stack(StackEvent::Left { .. }) => println!("left the network"),
                Event::Stack(StackEvent::Identify { .. }) => board.led.toggle(),
                Event::Commissioning(outcome) => println!("commissioning: {outcome:?}"),
                Event::Stack(other) => println!("{other:?}"),
            }
        }
        // The button: press to commission, hold to reset.
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
                    if node.stack.is_operating() {
                        println!("opening the network, finding & binding target");
                        let _ = node.open_network();
                        let _ = node.find_and_bind_target(LIGHT);
                    } else {
                        println!("steering");
                        let _ = node.steer();
                    }
                }
            }
            _ => {}
        }
        runner.idle_until(deadline, || board.button.is_low() != pressed);
    }
}
