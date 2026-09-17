//! GPDF parsing, Green Power cluster command codecs, Proxy Table entries
//! and the Basic Proxy never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use panweave_codec::Decode;
use panweave_green_power::cluster::{
    CommissioningNotification, GppGpdLink, Notification, Pairing, ProxyCommissioningMode,
    ProxyTableRequest, ProxyTableResponse,
};
use panweave_green_power::gpdf::Gpdf;
use panweave_green_power::proxy::{Proxy, ProxyConfig};
use panweave_green_power::proxy_table::ProxyTable;
use panweave_mac::frame::Frame as MacFrame;
use panweave_security::cipher::SoftwareAes;
use panweave_types::time::Instant;
use panweave_types::{ExtendedAddress, ShortAddress};

fuzz_target!(|data: &[u8]| {
    let _ = Notification::decode_exact(data);
    let _ = CommissioningNotification::decode_exact(data);
    let _ = ProxyCommissioningMode::decode_exact(data);
    let _ = ProxyTableRequest::decode_exact(data);
    let _ = ProxyTableResponse::decode_exact(data);
    let _ = ProxyTable::<4>::decode_entries(data);
    let mut proxy: Proxy<4> = Proxy::new(ProxyConfig::new(ShortAddress(1), ExtendedAddress(2)));
    proxy.poll(Instant::from_millis(1000));
    if let Ok(p) = Pairing::decode_exact(data) {
        proxy.on_pairing(&p, true);
    }
    if let Ok(m) = ProxyCommissioningMode::decode_exact(data) {
        proxy.on_commissioning_mode(&m, ShortAddress(3));
    }
    if let Ok(mac) = MacFrame::decode_exact(data)
        && let Ok(g) = Gpdf::decode(&mac)
    {
        proxy.on_gpdf::<SoftwareAes>(&g, GppGpdLink(0xC0));
    }
    while proxy.next_outgoing().is_some() {}
    while proxy.next_event().is_some() {}
});
