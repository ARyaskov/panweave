//! The Generic Tunnel server through the endpoint dispatcher (ZCL8
//! §9.2): a Match Protocol Address for its own protocol address is
//! answered with the device's IEEE address, any other is met with
//! silence on a multicast and a Default Response on a unicast.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_aps::layer::{DataIndication, Delivery, SecurityStatus};
use panweave_aps::tables::GroupTable;
use panweave_codec::{Decode, Encode, Writer};
use panweave_types::time::Instant;
use panweave_types::{Endpoint, ExtendedAddress, GroupAddress, ProfileId, ShortAddress};
use panweave_zcl::clusters::tunnels;
use panweave_zcl::clusters::{basic, identify};
use panweave_zcl::frame::{Direction, Frame, Header, ZclStatus};
use panweave_zcl::global::{DefaultResponse, command};
use panweave_zcl::layer::{EndpointInstance, Zcl, ZclAction};

const CLIENT: ShortAddress = ShortAddress(0x1234);
const EP: Endpoint = Endpoint(1);
const OWN: ExtendedAddress = ExtendedAddress(0x00aa_bbcc_ddee_ff01);
const ADDRESS: [u8; 3] = [0x00, 0x01, 0x2A];

type Node = Zcl<2, 12, 36>;

fn node() -> Node {
    let mut zcl = Node::new();
    zcl.set_ieee(OWN);
    let mut ep = EndpointInstance::new(EP, ProfileId::HOME_AUTOMATION);
    ep.add_instance(
        basic::server(basic::power_source::MAINS_SINGLE_PHASE, b"Panweave", b"Tun").unwrap(),
    )
    .unwrap();
    ep.add_instance(identify::server().unwrap()).unwrap();
    ep.add_instance(tunnels::generic_tunnel_server(504, 504, &ADDRESS).unwrap())
        .unwrap();
    ep.add_instance(tunnels::bacnet_tunnel_server()).unwrap();
    zcl.add_endpoint(ep).unwrap();
    zcl.poll_timers(Instant::from_millis(0));
    zcl
}

fn ind<'a>(asdu: &'a [u8], group: bool) -> DataIndication<'a> {
    DataIndication {
        src: CLIENT,
        src_endpoint: Endpoint(5),
        src_ieee: None,
        delivery: if group {
            Delivery::Group(GroupAddress(0x0007))
        } else {
            Delivery::Endpoint(EP)
        },
        profile: ProfileId::HOME_AUTOMATION,
        cluster: tunnels::GENERIC_TUNNEL,
        asdu,
        security: SecurityStatus::NwkKey,
        lqi: 200,
        relayed: None,
        counter: 0,
        nwk_broadcast: false,
    }
}

fn match_request(zcl: &mut Node, address: &[u8], group: bool) -> Option<(Header, Vec<u8>)> {
    let mut payload = [0u8; 8];
    let mut w = Writer::new(&mut payload);
    tunnels::encode_protocol_address(address, &mut w).unwrap();
    let n = w.position();
    let header = Header::cluster_specific(
        panweave_types::TransactionSequence(0x21),
        tunnels::CMD_MATCH_PROTOCOL_ADDRESS,
        Direction::ToServer,
    );
    let mut buf = [0u8; 64];
    let len = Frame {
        header,
        payload: &payload[..n],
    }
    .encode_to_slice(&mut buf)
    .unwrap();
    let mut groups = GroupTable::<4>::new();
    groups.add(GroupAddress(0x0007), EP).unwrap();
    while zcl.next_action().is_some() {}
    let out = zcl.on_data(&ind(&buf[..len], group), &mut groups);
    assert!(out.is_none(), "executed by the layer");
    match zcl.next_action()? {
        ZclAction::Send { frame, .. } => {
            let (h, n) = Header::decode_prefix(&frame).unwrap();
            Some((h, frame[n..].to_vec()))
        }
    }
}

#[test]
fn a_matching_protocol_address_is_answered_with_the_ieee_address() {
    let mut zcl = node();
    let (h, p) = match_request(&mut zcl, &ADDRESS, true).unwrap();
    assert_eq!(h.command, tunnels::CMD_MATCH_PROTOCOL_ADDRESS_RESPONSE);
    assert_eq!(h.control.direction, Direction::ToClient);
    let r = tunnels::MatchProtocolAddressResponse::parse(&p).unwrap();
    assert_eq!((r.device, r.protocol_address), (OWN, &ADDRESS[..]));
    // Another address: silence on the group, a Default Response on a
    // unicast.
    assert!(match_request(&mut zcl, &[0x00, 0x01, 0x2B], true).is_none());
    let (h, p) = match_request(&mut zcl, &[0x00, 0x01, 0x2B], false).unwrap();
    assert_eq!(h.command, command::DEFAULT_RESPONSE);
    assert_eq!(
        DefaultResponse::decode_exact(&p).unwrap().status,
        ZclStatus::Success
    );
    // The address changes: the new one matches.
    {
        let c = zcl
            .endpoint_mut(EP)
            .unwrap()
            .cluster_mut(tunnels::GENERIC_TUNNEL, panweave_zcl::Role::Server)
            .unwrap();
        assert!(tunnels::set_protocol_address(c, &[0x00, 0x01, 0x2B]));
    }
    let (h, _) = match_request(&mut zcl, &[0x00, 0x01, 0x2B], true).unwrap();
    assert_eq!(h.command, tunnels::CMD_MATCH_PROTOCOL_ADDRESS_RESPONSE);
}
