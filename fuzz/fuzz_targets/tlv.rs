//! Annex I TLV validation and typed global TLV parsing never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use panweave_codec::tlv::{TlvIter, TlvSet, is_global_encapsulation};
use panweave_nwk::tlv::GlobalTlvs;

fuzz_target!(|data: &[u8]| {
    for t in TlvIter::new(data) {
        let _ = t;
    }
    if let Ok(set) = TlvSet::validate(data, |_| false) {
        let _ = set.iter().count();
        let _ = set.key_negotiation_methods();
        let _ = set.fragmentation_parameters();
        let _ = set.router_information();
        let _ = set.symmetric_passphrase();
        let _ = set.configuration_parameters();
        let _ = set.device_capability_extension();
        let _ = set.joiner_encapsulation().map(|s| s.iter().count());
        let _ = set.beacon_appendix_encapsulation().map(|s| s.iter().count());
    }
    let _ = TlvSet::validate(data, is_global_encapsulation);
});
