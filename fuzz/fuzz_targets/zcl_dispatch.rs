//! The ZCL endpoint dispatcher with every layer-executed cluster (Basic,
//! Identify, Groups, Scenes, On/Off, Level Control, Poll Control) never
//! panics on arbitrary frames, and its timers keep running.
#![no_main]
use libfuzzer_sys::fuzz_target;
use panweave_aps::layer::{DataIndication, Delivery, SecurityStatus};
use panweave_aps::tables::GroupTable;
use panweave_types::time::{Duration, Instant};
use panweave_types::{ClusterId, Endpoint, GroupAddress, ProfileId, ShortAddress};
use panweave_zcl::clusters::{basic, groups, identify, level, on_off, poll_control, scenes};
use panweave_zcl::layer::{EndpointInstance, Zcl};

fuzz_target!(|data: &[u8]| {
    let mut zcl: Zcl<1, 8, 16> = Zcl::new();
    let mut ep = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    let _ = ep.add_instance(basic::server(1, b"fuzz", b"fuzz").unwrap());
    let _ = ep.add_instance(identify::server().unwrap());
    let _ = ep.add_instance(groups::server().unwrap());
    let _ = ep.add_instance(scenes::server().unwrap());
    let _ = ep.add_instance(on_off::server().unwrap());
    let _ = ep.add_instance(level::server(1, 254).unwrap());
    let _ = ep.add_instance(poll_control::server(2, 4, 480).unwrap());
    let _ = zcl.add_endpoint(ep);
    let mut groups = GroupTable::<4>::new();
    let _ = groups.add(GroupAddress(1), Endpoint(1));
    let mut now = Instant::from_millis(1000);
    zcl.poll_timers(now);
    // Each chunk: 1 control octet (cluster index, delivery) + frame.
    for chunk in data.chunks(24) {
        let Some((&ctl, frame)) = chunk.split_first() else {
            break;
        };
        let cluster = match ctl & 0x07 {
            0 => basic::ID,
            1 => identify::ID,
            2 => groups::ID,
            3 => scenes::ID,
            4 => on_off::ID,
            5 => level::ID,
            6 => poll_control::ID,
            _ => ClusterId(0x0402),
        };
        let delivery = match (ctl >> 3) & 0x03 {
            0 => Delivery::Endpoint(Endpoint(1)),
            1 => Delivery::Group(GroupAddress(1)),
            2 => Delivery::AllEndpoints,
            _ => Delivery::Endpoint(Endpoint(7)),
        };
        let ind = DataIndication {
            src: ShortAddress(0x1234),
            src_endpoint: Endpoint(5),
            src_ieee: None,
            delivery,
            profile: ProfileId::HOME_AUTOMATION,
            cluster,
            asdu: frame,
            security: if ctl & 0x20 != 0 {
                SecurityStatus::LinkKey
            } else {
                SecurityStatus::NwkKey
            },
            lqi: 200,
            relayed: None,
            counter: 0,
            nwk_broadcast: ctl & 0x40 != 0,
        };
        let _ = zcl.on_data(&ind, &mut groups);
        while zcl.next_action().is_some() {}
        while zcl.next_event().is_some() {}
        now += Duration::from_millis(u64::from(ctl >> 5) * 100 + 1);
        zcl.poll_timers(now);
        let _ = zcl.next_deadline();
    }
    // Run the timers well past every transition / countdown.
    for _ in 0..64 {
        now += Duration::from_millis(250);
        zcl.poll_timers(now);
        while zcl.next_action().is_some() {}
        while zcl.next_event().is_some() {}
    }
});
