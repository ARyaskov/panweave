//! The ZCL endpoint dispatcher: a Read Attributes request served from the
//! attribute store, an On command executed by the layer, and the
//! reporting engine's periodic scan of an idle endpoint.

use criterion::{Criterion, criterion_group, criterion_main};
use panweave_aps::layer::{DataIndication, Delivery, SecurityStatus};
use panweave_aps::tables::GroupTable;
use panweave_codec::Encode;
use panweave_types::time::{Duration, Instant};
use panweave_types::{ClusterId, Endpoint, ProfileId, ShortAddress, TransactionSequence};
use panweave_zcl::clusters::{basic, groups, identify, level, on_off, scenes};
use panweave_zcl::frame::{Direction, Frame, Header};
use panweave_zcl::global::command;
use panweave_zcl::layer::{EndpointInstance, Zcl};
use std::hint::black_box;

type Node = Zcl<1, 8, 16>;

fn lamp() -> Node {
    let mut zcl = Node::new();
    let mut ep = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    ep.add_instance(basic::server(1, b"Panweave", b"Bench").unwrap())
        .unwrap();
    ep.add_instance(identify::server().unwrap()).unwrap();
    ep.add_instance(groups::server().unwrap()).unwrap();
    ep.add_instance(scenes::server().unwrap()).unwrap();
    ep.add_instance(on_off::server().unwrap()).unwrap();
    ep.add_instance(level::server(1, 254).unwrap()).unwrap();
    zcl.add_endpoint(ep).unwrap();
    zcl.poll_timers(Instant::from_millis(1000));
    zcl
}

fn frame(header: &Header, payload: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 96];
    let n = Frame {
        header: *header,
        payload,
    }
    .encode_to_slice(&mut buf)
    .unwrap();
    buf[..n].to_vec()
}

fn ind<'a>(cluster: ClusterId, asdu: &'a [u8]) -> DataIndication<'a> {
    DataIndication {
        src: ShortAddress(0x1234),
        src_endpoint: Endpoint(5),
        src_ieee: None,
        delivery: Delivery::Endpoint(Endpoint(1)),
        profile: ProfileId::HOME_AUTOMATION,
        cluster,
        asdu,
        security: SecurityStatus::NwkKey,
        lqi: 200,
        relayed: None,
        counter: 0,
        nwk_broadcast: false,
    }
}

fn dispatch(c: &mut Criterion) {
    let mut group = c.benchmark_group("zcl-dispatch");
    let mut zcl = lamp();
    let mut groups = GroupTable::<4>::new();
    // Read Attributes: ZCLVersion, ManufacturerName, ModelIdentifier.
    let read = frame(
        &Header::global(
            TransactionSequence(1),
            command::READ_ATTRIBUTES,
            Direction::ToServer,
        ),
        &[0x00, 0x00, 0x04, 0x00, 0x05, 0x00],
    );
    group.bench_function("read-attributes/3", |b| {
        b.iter(|| {
            let _ = zcl.on_data(black_box(&ind(basic::ID, &read)), &mut groups);
            while zcl.next_action().is_some() {}
        });
    });
    let toggle = frame(
        &Header::cluster_specific(
            TransactionSequence(2),
            on_off::CMD_TOGGLE,
            Direction::ToServer,
        )
        .disable_default_response(true),
        &[],
    );
    group.bench_function("on-off/toggle", |b| {
        b.iter(|| {
            let _ = zcl.on_data(black_box(&ind(on_off::ID, &toggle)), &mut groups);
            while zcl.next_action().is_some() {}
            while zcl.next_event().is_some() {}
        });
    });
    let move_to = frame(
        &Header::cluster_specific(
            TransactionSequence(3),
            level::CMD_MOVE_TO_LEVEL_WITH_ON_OFF,
            Direction::ToServer,
        )
        .disable_default_response(true),
        &[200, 0, 0, 0, 0],
    );
    group.bench_function("level/move-to-level-immediate", |b| {
        b.iter(|| {
            let _ = zcl.on_data(black_box(&ind(level::ID, &move_to)), &mut groups);
            while zcl.next_action().is_some() {}
            while zcl.next_event().is_some() {}
        });
    });
    let mut now = Instant::from_millis(2000);
    group.bench_function("poll-timers/idle", |b| {
        b.iter(|| {
            now += Duration::from_millis(100);
            zcl.poll_timers(black_box(now));
            while zcl.next_action().is_some() {}
            while zcl.next_event().is_some() {}
        });
    });
    group.finish();
}

criterion_group!(benches, dispatch);
criterion_main!(benches);
