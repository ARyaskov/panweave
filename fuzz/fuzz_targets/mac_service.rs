//! The MAC service survives arbitrary received frames.
#![no_main]
use libfuzzer_sys::fuzz_target;
use panweave_mac::radio::RxMetadata;
use panweave_mac::service::{MacService, MacServiceConfig};
use panweave_types::time::Instant;
use panweave_types::{Channel, ChannelPage, ExtendedAddress, PanId, ShortAddress};

fuzz_target!(|data: &[u8]| {
    let mut s = MacService::new(MacServiceConfig::default(), ExtendedAddress(0xAA));
    s.start(
        PanId(0x1234),
        ChannelPage::PAGE_0,
        Channel::DEFAULT_2_4GHZ,
        ShortAddress(0x0000),
        true,
        true,
    );
    s.poll_timers(Instant::from_millis(1000));
    for chunk in data.split(|b| *b == 0xFF) {
        let _ = s.on_receive(chunk, RxMetadata::default());
        while s.next_action().is_some() {}
        while s.next_event().is_some() {}
    }
    s.poll_timers(Instant::from_millis(10_000));
});
