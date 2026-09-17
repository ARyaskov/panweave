//! Read / Write Attributes Structured against a server holding array,
//! structure and set attributes (ZCL8 §2.5.15 – §2.5.17).

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_aps::layer::{DataIndication, Delivery, SecurityStatus};
use panweave_aps::tables::GroupTable;
use panweave_codec::{Encode, Writer};
use panweave_types::time::Instant;
use panweave_types::{AttributeId, ClusterId, CommandId, Endpoint, ProfileId, ShortAddress};
use panweave_zcl::attribute::{Access, AttributeDef};
use panweave_zcl::frame::{Direction, Frame, Header, ZclStatus};
use panweave_zcl::global::{
    ReadAttributeStatus, ReadStructured, Records, WriteStructured, WriteStructuredStatus, command,
};
use panweave_zcl::layer::{EndpointInstance, Zcl, ZclAction};
use panweave_zcl::structured::{Selector, op};
use panweave_zcl::types::DataType;
use panweave_zcl::{ClusterDef, ClusterInstance, Role, Value as V};

const CLIENT: ShortAddress = ShortAddress(0x1234);
const EP: Endpoint = Endpoint(1);
const CLUSTER: ClusterId = ClusterId(0xfc01);
const ARRAY: AttributeId = AttributeId(0x0001);
const STRUCT: AttributeId = AttributeId(0x0002);
const SET: AttributeId = AttributeId(0x0003);

type Node = Zcl<2, 4, 8>;

fn server() -> Node {
    let mut zcl = Node::new();
    let mut ep = EndpointInstance::new(EP, ProfileId::HOME_AUTOMATION);
    let mut c: ClusterInstance<8> = ClusterInstance::new(
        ClusterDef {
            id: CLUSTER,
            revision: 1,
            received: &[],
            generated: &[],
        },
        Role::Server,
    );
    // Array of three uint8.
    c.add_attribute(
        AttributeDef::new(ARRAY.0, DataType::Array, Access::RW),
        &V::Composite {
            ty: DataType::Array,
            bytes: &[0x20, 3, 0, 10, 20, 30],
        },
    )
    .unwrap();
    // Struct { uint8 7, array of two uint16 [1, 2] }, read-only.
    c.add_attribute(
        AttributeDef::new(STRUCT.0, DataType::Struct, Access::RO),
        &V::Composite {
            ty: DataType::Struct,
            bytes: &[2, 0, 0x20, 7, 0x48, 0x21, 2, 0, 1, 0, 2, 0],
        },
    )
    .unwrap();
    // Set of uint8 {1, 2}.
    c.add_attribute(
        AttributeDef::new(SET.0, DataType::Set, Access::RW),
        &V::Composite {
            ty: DataType::Set,
            bytes: &[0x20, 2, 0, 1, 2],
        },
    )
    .unwrap();
    ep.add_instance(c).unwrap();
    zcl.add_endpoint(ep).unwrap();
    zcl.poll_timers(Instant::from_millis(1000));
    zcl
}

fn exchange(zcl: &mut Node, cmd: CommandId, payload: &[u8]) -> (Header, Vec<u8>) {
    let header = Header::global(
        panweave_types::TransactionSequence(0x33),
        cmd,
        Direction::ToServer,
    );
    let mut buf = [0u8; 96];
    let n = Frame { header, payload }.encode_to_slice(&mut buf).unwrap();
    let ind = DataIndication {
        src: CLIENT,
        src_endpoint: Endpoint(5),
        src_ieee: None,
        delivery: Delivery::Endpoint(EP),
        profile: ProfileId::HOME_AUTOMATION,
        cluster: CLUSTER,
        asdu: &buf[..n],
        security: SecurityStatus::NwkKey,
        lqi: 200,
        relayed: None,
        counter: 0,
        nwk_broadcast: false,
    };
    assert!(zcl.on_data(&ind, &mut GroupTable::<4>::new()).is_none());
    match zcl.next_action().unwrap() {
        ZclAction::Send { frame, .. } => {
            let (h, n) = Header::decode_prefix(&frame).unwrap();
            (h, frame[n..].to_vec())
        }
    }
}

fn u8v(v: u8) -> V<'static> {
    V::Uint {
        width: 1,
        value: u64::from(v),
    }
}

#[test]
fn read_structured_selects_elements_and_counts() {
    let mut zcl = server();
    let mut buf = [0u8; 64];
    let mut w = Writer::new(&mut buf);
    for (id, indices) in [
        (ARRAY, &[][..]),
        (ARRAY, &[2][..]),
        (ARRAY, &[0][..]),
        (STRUCT, &[2, 2][..]),
        (STRUCT, &[3][..]),
        (SET, &[1][..]),
        (AttributeId(0x0009), &[][..]),
    ] {
        ReadStructured {
            id,
            selector: Selector::element(indices).unwrap(),
        }
        .encode(&mut w)
        .unwrap();
    }
    let n = w.position();
    let (h, p) = exchange(&mut zcl, command::READ_ATTRIBUTES_STRUCTURED, &buf[..n]);
    assert_eq!(h.command, command::READ_ATTRIBUTES_RESPONSE);
    let recs: Vec<ReadAttributeStatus> = Records::new(&p).map(Result::unwrap).collect();
    assert_eq!(recs.len(), 7);
    assert_eq!(
        recs[0].value,
        Some(V::Composite {
            ty: DataType::Array,
            bytes: &[0x20, 3, 0, 10, 20, 30]
        })
    );
    assert_eq!(recs[1].value, Some(u8v(20)));
    assert_eq!(recs[2].value, Some(V::Uint { width: 2, value: 3 }));
    assert_eq!(recs[3].value, Some(V::Uint { width: 2, value: 2 }));
    assert_eq!(recs[4].status, ZclStatus::InvalidSelector);
    assert_eq!(
        recs[5].status,
        ZclStatus::InvalidSelector,
        "sets are not element-readable"
    );
    assert_eq!(recs[6].status, ZclStatus::UnsupportedAttribute);
}

#[test]
fn write_structured_replaces_adds_and_removes() {
    let mut zcl = server();
    let mut buf = [0u8; 64];
    let mut w = Writer::new(&mut buf);
    // Replace the third array element, add 3 to the set, remove 1.
    WriteStructured {
        id: ARRAY,
        selector: Selector::element(&[3]).unwrap(),
        value: u8v(99),
    }
    .encode(&mut w)
    .unwrap();
    WriteStructured {
        id: SET,
        selector: Selector {
            op: op::ADD,
            indices: heapless::Vec::new(),
        },
        value: u8v(3),
    }
    .encode(&mut w)
    .unwrap();
    WriteStructured {
        id: SET,
        selector: Selector {
            op: op::REMOVE,
            indices: heapless::Vec::new(),
        },
        value: u8v(1),
    }
    .encode(&mut w)
    .unwrap();
    let n = w.position();
    let (h, p) = exchange(&mut zcl, command::WRITE_ATTRIBUTES_STRUCTURED, &buf[..n]);
    assert_eq!(h.command, command::WRITE_ATTRIBUTES_STRUCTURED_RESPONSE);
    let st: Vec<WriteStructuredStatus> = Records::new(&p).map(Result::unwrap).collect();
    assert_eq!(
        st,
        vec![WriteStructuredStatus {
            status: ZclStatus::Success,
            target: None
        }]
    );
    let c = zcl.cluster(EP, CLUSTER, Role::Server).unwrap();
    assert_eq!(
        c.attributes.value(ARRAY).unwrap(),
        V::Composite {
            ty: DataType::Array,
            bytes: &[0x20, 3, 0, 10, 20, 99]
        }
    );
    assert_eq!(
        c.attributes.value(SET).unwrap(),
        V::Composite {
            ty: DataType::Set,
            bytes: &[0x20, 2, 0, 2, 3]
        }
    );

    // Failures: wrong element type, index past the end, a read-only
    // struct, a duplicate set element, the array length (read-only).
    let mut w = Writer::new(&mut buf);
    WriteStructured {
        id: ARRAY,
        selector: Selector::element(&[1]).unwrap(),
        value: V::Uint { width: 2, value: 1 },
    }
    .encode(&mut w)
    .unwrap();
    WriteStructured {
        id: ARRAY,
        selector: Selector::element(&[4]).unwrap(),
        value: u8v(1),
    }
    .encode(&mut w)
    .unwrap();
    WriteStructured {
        id: STRUCT,
        selector: Selector::element(&[1]).unwrap(),
        value: u8v(1),
    }
    .encode(&mut w)
    .unwrap();
    WriteStructured {
        id: SET,
        selector: Selector {
            op: op::ADD,
            indices: heapless::Vec::new(),
        },
        value: u8v(2),
    }
    .encode(&mut w)
    .unwrap();
    WriteStructured {
        id: ARRAY,
        selector: Selector::element(&[0]).unwrap(),
        value: V::Uint { width: 2, value: 5 },
    }
    .encode(&mut w)
    .unwrap();
    let n = w.position();
    let (_, p) = exchange(&mut zcl, command::WRITE_ATTRIBUTES_STRUCTURED, &buf[..n]);
    let st: Vec<WriteStructuredStatus> = Records::new(&p).map(Result::unwrap).collect();
    let statuses: Vec<(ZclStatus, AttributeId, Vec<u16>)> = st
        .iter()
        .map(|s| {
            let (id, sel) = s.target.clone().unwrap();
            (s.status, id, sel.indices.to_vec())
        })
        .collect();
    assert_eq!(
        statuses,
        vec![
            (ZclStatus::InvalidDataType, ARRAY, vec![1]),
            (ZclStatus::InvalidSelector, ARRAY, vec![4]),
            (ZclStatus::ReadOnly, STRUCT, vec![1]),
            (ZclStatus::DuplicateExists, SET, vec![]),
            (ZclStatus::ReadOnly, ARRAY, vec![0]),
        ]
    );
    // A whole-attribute structured write behaves like Write Attributes.
    let mut w = Writer::new(&mut buf);
    WriteStructured {
        id: ARRAY,
        selector: Selector::WHOLE,
        value: V::Composite {
            ty: DataType::Array,
            bytes: &[0x20, 1, 0, 5],
        },
    }
    .encode(&mut w)
    .unwrap();
    let n = w.position();
    let (_, p) = exchange(&mut zcl, command::WRITE_ATTRIBUTES_STRUCTURED, &buf[..n]);
    let st: Vec<WriteStructuredStatus> = Records::new(&p).map(Result::unwrap).collect();
    assert_eq!(st[0].status, ZclStatus::Success);
    let c = zcl.cluster(EP, CLUSTER, Role::Server).unwrap();
    assert_eq!(
        c.attributes.value(ARRAY).unwrap(),
        V::Composite {
            ty: DataType::Array,
            bytes: &[0x20, 1, 0, 5]
        }
    );
}
