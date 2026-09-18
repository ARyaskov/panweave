//! Panweave on the ESP32-C6 Super Mini.
//!
//! The ESP32-C6 has an IEEE 802.15.4 radio, driven bare-metal by
//! `esp-radio`; this crate is the glue between it and the sans-I/O
//! Panweave stack:
//!
//! * [`radio::Radio`] executes the stack's [`MacAction`]s on the radio
//!   and turns received frames into [`Node::on_radio_frame`] calls;
//! * [`board::Board`] brings the chip up: clock, TRNG, the on-chip flash
//!   as the stack's [`Storage`] (`panweave_storage::nor_flash`), the
//!   IEEE address from the eFuse MAC, the LED and the BOOT button;
//! * [`runner::run`] is the main loop: poll the stack at its deadlines,
//!   drive the radio, hand events to the application.
//!
//! The binaries in `src/bin` are the example firmware: a router On/Off
//! Light, a coordinator, an On/Off switch and a temperature sensor.
//! `docs/esp32c6.md` in the repository is the guide.
//!
//! [`MacAction`]: panweave::mac::service::MacAction
//! [`Node::on_radio_frame`]: panweave::Node::on_radio_frame
//! [`Storage`]: panweave::storage::Storage

#![no_std]
#![warn(missing_docs)]

pub mod board;
pub mod radio;
pub mod runner;

pub use board::{Board, FlashStore, Rng};
pub use radio::Radio;
pub use runner::{Runner, now};
