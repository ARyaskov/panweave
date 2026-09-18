//! A Zigbee 4.0 Temperature Sensor on the ESP32-C6 Super Mini.
//!
//! An rx-on end device reporting the chip's own die temperature (the
//! Super Mini has no other sensor; it reads a few degrees above the
//! room). The Temperature Measurement server's `MeasuredValue` is
//! refreshed every ten seconds and the stack's default reporting sends
//! it to the bound client on change (0.5 °C) and at least every five
//! minutes. Factory new, the sensor steers into an open network; a
//! press of BOOT on the network runs finding & binding as the initiator
//! towards an identifying target (the coordinator after its button).
//! Holding BOOT for three seconds factory-resets the sensor.
//!
//! Flash and watch: `cargo run --release --bin temperature_sensor`.

#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_println::println;
use panweave::runtime::StackEvent;
use panweave::security::cipher::SoftwareAes;
use panweave::types::Endpoint;
use panweave::zcl::Role;
use panweave::zcl::clusters::measurement::temperature;
use panweave::zcl::types::Value;
use panweave::{EndDevice, Event, endpoints};
use panweave_esp32c6::{Board, Runner, now};

esp_bootloader_esp_idf::esp_app_desc!();

const SENSOR: Endpoint = Endpoint(1);
const SAMPLE_MS: u64 = 10_000;

#[esp_hal::main]
fn main() -> ! {
    let mut board = Board::init();
    println!("panweave temperature sensor, IEEE {:?}", board.ieee);
    let mut node = EndDevice::new(board.ieee)
        .identity(b"panweave", b"esp32c6-tsens")
        .build::<SoftwareAes, _, _>(board.rng, board.storage);
    let (descriptor, endpoint) = endpoints::temperature_sensor(SENSOR).expect("sensor endpoint");
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
    let mut next_sample = 0u64;
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
                }
                Event::Stack(StackEvent::Left { .. }) => println!("left the network"),
                Event::Stack(StackEvent::Identify { .. }) => board.led.toggle(),
                Event::Commissioning(outcome) => println!("commissioning: {outcome:?}"),
                Event::Stack(other) => println!("{other:?}"),
            }
        }
        if now().as_millis() >= next_sample {
            next_sample = now().as_millis() + SAMPLE_MS;
            let celsius = panweave_esp32c6::board::temperature_celsius(&board.tsens);
            // MeasuredValue is in hundredths of a degree (ZCL8 §4.4.2.2.1).
            #[allow(clippy::cast_possible_truncation)]
            let hundredths = (celsius * 100.0) as i64;
            if let Some(c) = node
                .stack
                .zcl
                .cluster_mut(SENSOR, temperature::ID, Role::Server)
            {
                let v = Value::Int {
                    width: 2,
                    value: hundredths,
                };
                match c.attributes.set(temperature::MEASURED_VALUE.id, &v) {
                    Ok(changed) => {
                        if changed {
                            println!("temperature {celsius:.2} °C");
                        }
                    }
                    Err(e) => println!("measured value: {e:?}"),
                }
            }
            node.stack.flush();
        }
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
                        println!("finding & binding: looking for an identifying client");
                        let _ = node.find_and_bind_initiator(SENSOR, None, &[temperature::ID]);
                    } else {
                        println!("steering");
                        let _ = node.steer();
                    }
                }
            }
            _ => {}
        }
        let wake_at = deadline.map_or(next_sample, |d| d.as_millis().min(next_sample));
        runner.idle_until(
            Some(panweave::types::time::Instant::from_millis(wake_at)),
            || board.button.is_low() != pressed,
        );
    }
}
