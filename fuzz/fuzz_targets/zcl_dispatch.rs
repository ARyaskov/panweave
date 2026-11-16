//! Stateful dispatch across the general, safety, HVAC and appliance
//! servers, including full-length commands and timer transitions.
#![no_main]
use libfuzzer_sys::fuzz_target;

#[path = "../../panweave-zcl/tests/support/dispatcher.rs"]
mod dispatcher;

fuzz_target!(|data: &[u8]| {
    let _ = dispatcher::drive(data);
});
