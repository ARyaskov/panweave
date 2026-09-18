//! A Zigbee Direct device end to end: the facade `Node` as the ZDD behind
//! the Commissioning Service: a coordinator formed through a Form
//! Network write, opened through Permit Joining, a router joined through
//! Join Network (MAC association), another adopted out of band, and a
//! Leave Network, with the Commissioning Status notifications a ZVD
//! would receive (ZD 1.1 §7.7.2).

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave::mac::radio::{RxMetadata, TxResult};
use panweave::mac::service::MacAction;
use panweave::runtime::StackEvent;
use panweave::security::cipher::SoftwareAes;
use panweave::storage::MemoryStorage;
use panweave::testkit::{TestRng, VirtualClock, VirtualMedium};
use panweave::types::time::Duration;
use panweave::types::{Channel, ChannelMask, ExtendedAddress, Key128, PanId, ShortAddress};
use panweave::{Coordinator, Event, Node, Router};
use panweave_direct::auth::Level;
use panweave_direct::commissioning::{
    Access, Characteristic, Commissioning, DeviceType, Domain, FormNetwork, JoinNetwork,
    JoinedStatus, JoiningMethod, LeaveNetwork, decode_status,
};

type N = Node<SoftwareAes, TestRng, MemoryStorage<64, 128>>;

/// Minimal host loop over the virtual medium.
struct World {
    medium: VirtualMedium,
    clock: VirtualClock,
    nodes: Vec<(N, usize, Vec<Event>)>,
}

impl World {
    fn add(&mut self, mut node: N) -> usize {
        let radio = self.medium.add_radio();
        node.poll(self.clock.now());
        self.nodes.push((node, radio, Vec::new()));
        self.nodes.len() - 1
    }

    fn settle(&mut self) {
        loop {
            let mut moved = false;
            for i in 0..self.nodes.len() {
                while let Some(a) = self.nodes[i].0.next_radio_action() {
                    moved = true;
                    match a {
                        MacAction::Transmit { frame, .. } => {
                            let now = self.clock.now();
                            let radio = self.nodes[i].1;
                            let (air, targets) = self.medium.transmit(radio, &frame);
                            if let Some(air) = air {
                                for t in targets {
                                    if let Some(j) = self.nodes.iter().position(|n| n.1 == t) {
                                        self.nodes[j].0.on_radio_frame(
                                            &air.bytes,
                                            RxMetadata {
                                                lqi: 200,
                                                rssi_dbm: -40,
                                                timestamp_us: None,
                                                acked_by_hardware: false,
                                                channel: Some(air.channel),
                                            },
                                        );
                                    }
                                }
                            }
                            self.nodes[i].0.on_tx_complete(Ok(TxResult {
                                acked: false,
                                frame_pending: false,
                                timestamp_us: Some(now.as_millis() * 1000),
                            }));
                        }
                        MacAction::SetChannel { channel, .. } => {
                            let radio = self.nodes[i].1;
                            self.medium.set_channel(radio, channel);
                        }
                        MacAction::EnergyDetect { .. } => self.nodes[i].0.on_energy_result(0),
                        MacAction::Configure(_) | MacAction::SetPending { .. } => {}
                    }
                }
                while let Some(e) = self.nodes[i].0.next_event() {
                    moved = true;
                    self.nodes[i].2.push(e);
                }
            }
            if !moved {
                break;
            }
        }
    }

    fn run_until(&mut self, timeout: Duration, mut pred: impl FnMut(&World) -> bool) -> bool {
        let end = self.clock.now() + timeout;
        loop {
            self.settle();
            if pred(self) {
                return true;
            }
            if self.clock.now().as_millis() >= end.as_millis() {
                return false;
            }
            let now = self.clock.now();
            let next = self
                .nodes
                .iter()
                .filter_map(|n| n.0.next_deadline())
                .min_by_key(|t| t.as_millis())
                .map_or(now + Duration::from_millis(250), |t| {
                    if t.as_millis() <= now.as_millis() {
                        now + Duration::from_millis(1)
                    } else {
                        t
                    }
                });
            let target = if next.as_millis() > now.as_millis() + 250 {
                now + Duration::from_millis(250)
            } else {
                next
            };
            self.clock.advance_to(target);
            for n in &mut self.nodes {
                n.0.poll(target);
            }
        }
    }
}

fn direct_done(w: &World, i: usize, d: Domain) -> Option<u8> {
    w.nodes[i].2.iter().find_map(|e| match e {
        Event::Direct { domain, status } if *domain == d => Some(*status),
        _ => None,
    })
}

fn report(w: &mut World, i: usize, svc: &mut Commissioning, d: Domain) -> Vec<u8> {
    let status = direct_done(w, i, d).expect("operation completed");
    svc.report(&w.nodes[i].0, d, status);
    w.nodes[i].2.clear();
    svc.next_notification().expect("notification").to_vec()
}

#[test]
fn zdd_form_open_join_adopt_and_leave() {
    let mut w = World {
        medium: VirtualMedium::new(),
        clock: VirtualClock::new(),
        nodes: Vec::new(),
    };
    let channel = Channel::new_2_4ghz(15).unwrap();
    let mask = ChannelMask::EMPTY.with(channel);
    let nwk_key = Key128::from_bytes([0x5a; 16]);

    let mut coord = Coordinator::new(ExtendedAddress(0x00DD_0000_0000_0001))
        .build::<SoftwareAes, _, _>(TestRng::seed(1), MemoryStorage::new());
    coord.stack.config.trust_center_policy.allow_joins = true;
    let c = w.add(coord);

    // Form Network over a provisioning session: PAN ID, channel and
    // network key chosen by the ZVD.
    let mut zvd_c = Commissioning::new(Level::Provisioning, false);
    let mut buf = [0u8; 128];
    let n = FormNetwork {
        pan_id: Some(PanId(0x1A62)),
        channels: Some(mask),
        network_key: Some(nwk_key.clone()),
        ..FormNetwork::default()
    }
    .encode(&mut buf)
    .unwrap();
    assert_eq!(
        zvd_c.write(&mut w.nodes[c].0, Characteristic::FormNetwork, &buf[..n]),
        Access::Ok
    );
    assert!(zvd_c.next_notification().is_none());
    assert!(w.run_until(Duration::from_secs(30), |w| {
        direct_done(w, c, Domain::FormNetwork).is_some()
    }));
    let note = report(&mut w, c, &mut zvd_c, Domain::FormNetwork);
    let (r, code) = decode_status(&note).unwrap();
    assert!(code.is_none());
    let r = r.unwrap();
    assert_eq!(r.status.joined, JoinedStatus::Commissioned);
    assert!(r.status.centralized && !r.status.open);
    let info = r.network.unwrap();
    assert_eq!(info.pan_id, PanId(0x1A62));
    assert_eq!(info.channel, mask);
    assert_eq!(info.device_type, DeviceType::Coordinator);
    assert_eq!(info.nwk_address, ShortAddress(0));
    let epid = info.extended_pan_id;
    // The provisioning session lost its write access once provisioned.
    assert_eq!(
        zvd_c.write(&mut w.nodes[c].0, Characteristic::PermitJoining, &[60]),
        Access::Unauthorized
    );
    let mut admin_c = Commissioning::new(Level::Admin, true);
    assert_eq!(
        admin_c.write(&mut w.nodes[c].0, Characteristic::PermitJoining, &[120]),
        Access::Ok
    );
    let (r, _) = decode_status(&admin_c.next_notification().unwrap()).unwrap();
    assert!(r.unwrap().status.open);
    w.settle();

    // A router ZDD joins by MAC association on the given channel and
    // extended PAN ID.
    let router = Router::new(ExtendedAddress(0x00DD_0000_0000_0002))
        .build::<SoftwareAes, _, _>(TestRng::seed(2), MemoryStorage::new());
    let r1 = w.add(router);
    let mut zvd_r = Commissioning::new(Level::Provisioning, false);
    let n = JoinNetwork {
        method: JoiningMethod::Association,
        extended_pan_id: Some(epid),
        pan_id: None,
        channels: Some(mask),
        network_key: None,
        link_key: None,
        nwk_address: None,
        trust_center: None,
        update_id: None,
        key_sequence: None,
        admin_key: None,
    }
    .encode(&mut buf)
    .unwrap();
    assert_eq!(
        zvd_r.write(&mut w.nodes[r1].0, Characteristic::JoinNetwork, &buf[..n]),
        Access::Ok
    );
    assert!(
        w.run_until(Duration::from_secs(120), |w| direct_done(
            w,
            r1,
            Domain::JoinNetwork
        )
        .is_some()),
        "{:?}",
        w.nodes[r1].2
    );
    let note = report(&mut w, r1, &mut zvd_r, Domain::JoinNetwork);
    let (r, code) = decode_status(&note).unwrap();
    assert!(code.is_none(), "{code:?}");
    let info = r.unwrap().network.unwrap();
    assert_eq!(info.extended_pan_id, epid);
    assert_eq!(info.pan_id, PanId(0x1A62));
    assert_eq!(info.trust_center, ExtendedAddress(0x00DD_0000_0000_0001));
    assert_eq!(info.device_type, DeviceType::Router);
    assert!(w.nodes[r1].0.stack.is_operating());

    // A second router is provisioned out of band with the full parameter
    // set and is on the network at once: the coordinator hears its
    // Device_annce.
    let router = Router::new(ExtendedAddress(0x00DD_0000_0000_0003))
        .build::<SoftwareAes, _, _>(TestRng::seed(3), MemoryStorage::new());
    let r2 = w.add(router);
    let mut zvd_r2 = Commissioning::new(Level::Provisioning, false);
    let n = JoinNetwork {
        method: JoiningMethod::OutOfBand,
        extended_pan_id: Some(epid),
        pan_id: Some(PanId(0x1A62)),
        channels: Some(mask),
        network_key: Some(nwk_key),
        link_key: None,
        nwk_address: Some(ShortAddress(0x3344)),
        trust_center: Some(ExtendedAddress(0x00DD_0000_0000_0001)),
        update_id: Some(0),
        key_sequence: Some(0),
        admin_key: None,
    }
    .encode(&mut buf)
    .unwrap();
    assert_eq!(
        zvd_r2.write(&mut w.nodes[r2].0, Characteristic::JoinNetwork, &buf[..n]),
        Access::Ok
    );
    assert!(w.run_until(Duration::from_secs(10), |w| {
        direct_done(w, r2, Domain::JoinNetwork).is_some()
    }));
    let note = report(&mut w, r2, &mut zvd_r2, Domain::JoinNetwork);
    let (r, _) = decode_status(&note).unwrap();
    assert_eq!(
        r.unwrap().network.unwrap().nwk_address,
        ShortAddress(0x3344)
    );
    assert!(
        w.run_until(Duration::from_secs(10), |w| w.nodes[c].2.iter().any(
            |e| matches!(
                e,
                Event::Stack(StackEvent::DeviceAnnounce {
                    ieee: ExtendedAddress(0x00DD_0000_0000_0003),
                    short: ShortAddress(0x3344),
                    ..
                })
            )
        ))
    );

    // Leave Network needs admin access on a provisioned ZDD.
    assert_eq!(
        zvd_r.write(&mut w.nodes[r1].0, Characteristic::LeaveNetwork, &[0, 0]),
        Access::Unauthorized
    );
    let mut admin_r = Commissioning::new(Level::Admin, true);
    let leave = LeaveNetwork {
        remove_children: false,
        rejoin: false,
    }
    .encode();
    assert_eq!(
        admin_r.write(&mut w.nodes[r1].0, Characteristic::LeaveNetwork, &leave),
        Access::Ok
    );
    assert!(w.run_until(Duration::from_secs(30), |w| {
        direct_done(w, r1, Domain::LeaveNetwork).is_some()
    }));
    let note = report(&mut w, r1, &mut admin_r, Domain::LeaveNetwork);
    let (r, code) = decode_status(&note).unwrap();
    assert_eq!(code, None);
    assert_eq!(r.unwrap().status.joined, JoinedStatus::NotCommissioned);
    assert_eq!(direct_done(&w, r1, Domain::LeaveNetwork), None);
}

/// Network key rotation (ZD 1.1 §9.1): the ZDD keeps the network key it
/// switched away from, persists it, and a ZVD whose Basic authorization
/// key was derived from that key still gets a Limited Authorization
/// session; the Transport Key filter keeps network keys off the tunnel.
#[test]
fn zdd_keeps_past_network_keys_for_limited_authorization() {
    use panweave::types::{Key128, KeySequenceNumber};
    use panweave_direct::rotation::{Forwarding, SessionClass, forwarding_decision};
    use panweave_direct::session::{Initiator, Responder, Secret};
    use panweave_direct::tlv::{Method, Psk};

    let mut w = World {
        medium: VirtualMedium::new(),
        clock: VirtualClock::new(),
        nodes: Vec::new(),
    };
    let old_key = Key128::from_bytes([0x5a; 16]);
    let mut coord = Coordinator::new(ExtendedAddress(0x00DD_0000_0000_0001))
        .build::<SoftwareAes, _, _>(TestRng::seed(1), MemoryStorage::new());
    coord.stack.config.trust_center_policy.allow_joins = true;
    let c = w.add(coord);
    w.nodes[c].0.form_network_with_key(old_key.clone()).unwrap();
    assert!(w.run_until(Duration::from_secs(30), |w| {
        w.nodes[c]
            .2
            .iter()
            .any(|e| matches!(e, Event::Stack(StackEvent::NetworkFormed { .. })))
    }));
    assert!(w.nodes[c].0.direct.past_network_keys.is_empty());
    // A first rotation gives the network a non-zero sequence number
    // (the session TLV treats 0 as "none").
    let old_key = Key128::from_bytes([0xa5; 16]);
    let old_seq = w.nodes[c]
        .0
        .stack
        .update_network_key(old_key.clone())
        .unwrap();
    assert!(w.run_until(Duration::from_secs(60), |w| {
        w.nodes[c].2.iter().any(|e| {
            matches!(
                e,
                Event::Stack(StackEvent::NetworkKeySwitched { sequence, .. }) if *sequence == old_seq
            )
        })
    }));
    assert_eq!(w.nodes[c].0.direct.past_network_keys.len(), 1);

    // The ZVD derived its Basic key from the current network key.
    let zvd = ExtendedAddress(0x001F_EE00_0000_0001);
    let basic_old = panweave_direct::auth::basic_key::<SoftwareAes>(zvd, &old_key);

    // The Trust Center rotates the key.
    let new_key = Key128::from_bytes([0xc3; 16]);
    let new_seq = w.nodes[c]
        .0
        .stack
        .update_network_key(new_key.clone())
        .unwrap();
    assert!(w.run_until(Duration::from_secs(60), |w| {
        w.nodes[c].2.iter().any(|e| {
            matches!(
                e,
                Event::Stack(StackEvent::NetworkKeySwitched { sequence, .. }) if *sequence == new_seq
            )
        })
    }));
    assert_eq!(
        w.nodes[c].0.direct.past_network_keys.get(old_seq),
        Some(&old_key)
    );
    // Persisted: a restart restores it.
    let storage = w.nodes[c].0.stack.storage.clone();
    let mut again = Coordinator::new(ExtendedAddress(0x00DD_0000_0000_0001))
        .build::<SoftwareAes, _, _>(TestRng::seed(2), storage);
    again.restore_direct_past_keys().unwrap();
    assert_eq!(again.direct.past_network_keys.get(old_seq), Some(&old_key));

    // A ZVD opening a session with the old Basic key and the old
    // sequence number gets a Limited Authorization session (§9.1).
    let zdd_ieee = ExtendedAddress(0x00DD_0000_0000_0001);
    let past = w.nodes[c].0.direct.past_network_keys.clone();
    let active = new_seq;
    let secrets = move |psk: Psk, seq: Option<u8>| -> Option<Secret<'static>> {
        match (psk, seq) {
            (Psk::BasicAuthorization, Some(s)) if s != active.0 => {
                let k = past.basic_key::<SoftwareAes>(zvd, KeySequenceNumber(s))?;
                Some(Secret::Key(Box::leak(Box::new(k))))
            }
            _ => None,
        }
    };
    let secrets: &'static dyn Fn(Psk, Option<u8>) -> Option<Secret<'static>> =
        Box::leak(Box::new(secrets));
    let mut rng = TestRng::seed(9);
    let mut zdd = Responder::new(Method::Curve25519AesMmo, zdd_ieee, Some(new_seq.0), secrets);
    let mut zvd_side = Initiator::new(Method::Curve25519AesMmo, zvd, Psk::BasicAuthorization);
    let m1 = zvd_side
        .message1::<SoftwareAes, _>(&mut rng, &Secret::Key(&basic_old), Some(old_seq.0))
        .unwrap();
    let m2 = zdd.on_message1::<SoftwareAes, _>(&mut rng, &m1).unwrap();
    let m3 = zvd_side.on_message2::<SoftwareAes>(&m2).unwrap();
    let (m4, established) = zdd.on_message3::<SoftwareAes>(&m3).unwrap();
    let on_zvd = zvd_side.on_message4::<SoftwareAes>(&m4).unwrap();
    assert_eq!(on_zvd.key, established.key);
    // The ZVD sees the rotation in Message 2; the ZDD classifies the
    // session as Limited.
    assert_eq!(on_zvd.key_sequence, Some(new_seq.0));
    assert_eq!(established.peer_key_sequence, Some(old_seq.0));
    assert_eq!(
        SessionClass::classify(established.psk, established.peer_key_sequence, new_seq),
        SessionClass::Limited
    );
    // The ZDD never tunnels the Transport Key that would carry the new
    // network key to the ZVD (§9).
    assert_eq!(
        forwarding_decision(&[0x01, 0x10, 0x05, 0x01]),
        Forwarding::Decline
    );
}

/// A ZVD joins through the Tunnel Service (ZD 1.1 §7.7.4.3): its Network
/// Commissioning Request arrives as an NPDU Message TLV, the response
/// and the Trust Center's key transport go back over the tunnel, and
/// afterwards the ZVD exchanges NWK frames with the network as a
/// neighbour behind the Trusted Link.
#[test]
fn zvd_joins_and_talks_through_the_tunnel() {
    use panweave::aps::frame::{Addressing, Header as ApsHeader};
    use panweave::codec::{Decode, Encode, Writer};
    use panweave::nwk::command::{CommissioningRequest, CommissioningType, NwkCommand};
    use panweave::nwk::frame::{FrameType, Header};
    use panweave::nwk::tlv::{
        DeviceCapabilityExtension, FragmentationParameters, SupportedKeyNegotiationMethods, tag,
        write_encapsulation,
    };
    use panweave::security::authorization::basic_key;
    use panweave::types::{ClusterId, Endpoint, MacCapability, MacStatus, ProfileId};
    use panweave_direct::tunnel::{NpduMessage, SessionKind, TunnelError};

    /// The Joiner Encapsulation of a ZVD (§7.7.4.3), or without the
    /// Device Capability Extension.
    fn joiner_tlvs(virtual_device: bool) -> Vec<u8> {
        let mut buf = [0u8; 48];
        let mut w = Writer::new(&mut buf);
        write_encapsulation(&mut w, tag::JOINER_ENCAPSULATION, |w| {
            SupportedKeyNegotiationMethods {
                protocols: 0x01,
                secrets: 0x01,
                source: None,
            }
            .write(w)?;
            FragmentationParameters {
                node: ShortAddress(0x4E21),
                options: 0,
                max_incoming_transfer_unit: 128,
            }
            .write(w)?;
            if virtual_device {
                DeviceCapabilityExtension(DeviceCapabilityExtension::ZIGBEE_DIRECT_VIRTUAL_DEVICE)
                    .write(w)?;
            }
            Ok(())
        })
        .unwrap();
        let n = w.position();
        buf[..n].to_vec()
    }

    let mut w = World {
        medium: VirtualMedium::new(),
        clock: VirtualClock::new(),
        nodes: Vec::new(),
    };
    let zdd_ieee = ExtendedAddress(0x00DD_0000_0000_0002);
    let mut coord = Coordinator::new(zdd_ieee)
        .build::<SoftwareAes, _, _>(TestRng::seed(7), MemoryStorage::new());
    coord.stack.config.trust_center_policy.allow_joins = true;
    coord.stack.config.trust_center_policy.allow_virtual_devices = true;
    let c = w.add(coord);
    let nwk_key = Key128::from_bytes([0x5a; 16]);
    w.nodes[c]
        .0
        .stack
        .form_network_with_key(nwk_key.clone())
        .unwrap();
    assert!(w.run_until(Duration::from_secs(30), |w| {
        w.nodes[c]
            .2
            .iter()
            .any(|e| matches!(e, Event::Stack(StackEvent::NetworkFormed { .. })))
    }));
    w.nodes[c].0.stack.permit_join_network(180).unwrap();
    w.settle();
    w.nodes[c].2.clear();
    // The tunnel opens for the ZVD on BLE connection 0x0042 as link 1.
    let zvd = ExtendedAddress(0x00AD_0000_0000_0009);
    let wanted = ShortAddress(0x4E21);
    assert!(w.nodes[c].0.open_tunnel(1, 0x0042, zvd));
    // Network Commissioning Request, unsecured, over the provisioning
    // session. Without the Device Capability Extension the ZDD drops it
    // (§7.7.4.8); with it, the join proceeds.
    let header = Header::new(FrameType::Command, ShortAddress::COORDINATOR, wanted, 1, 1)
        .with_src_ieee(zvd)
        .with_dst_ieee(zdd_ieee);
    let capability = MacCapability(0)
        .with_rx_on_when_idle(true)
        .with_allocate_address(true);
    let mut tlv = [0u8; 160];
    for (virtual_device, seq) in [(false, 1u8), (true, 2)] {
        let tlvs = joiner_tlvs(virtual_device);
        let cmd = NwkCommand::CommissioningRequest(CommissioningRequest {
            kind: CommissioningType::InitialJoin,
            capability,
            tlvs: &tlvs,
        });
        let mut npdu = [0u8; 120];
        let header = Header {
            sequence: seq,
            ..header
        };
        let h = header.encode_to_slice(&mut npdu).unwrap();
        let n = cmd.encode_to_slice(&mut npdu[h..]).unwrap();
        let t = NpduMessage {
            assume_security: false,
            npdu: &npdu[..h + n],
        }
        .encode(&mut tlv)
        .unwrap();
        let r = w.nodes[c]
            .0
            .on_tunnel_write(1, SessionKind::ZvdProvisioning, &tlv[..t]);
        if virtual_device {
            r.unwrap();
        } else {
            assert_eq!(r, Err(TunnelError::Dropped));
            w.settle();
            assert!(w.nodes[c].2.is_empty());
            assert!(w.nodes[c].0.stack.nwk.neighbors.by_extended(zvd).is_none());
        }
    }
    assert!(w.run_until(Duration::from_secs(5), |w| {
        w.nodes[c]
            .2
            .iter()
            .filter(|e| matches!(e, Event::DirectTunnel { link: 1, .. }))
            .count()
            >= 2
    }));
    let out: Vec<NpduMessage<'_>> = w.nodes[c]
        .2
        .iter()
        .filter_map(|e| match e {
            Event::DirectTunnel { tlv, .. } => Some(tlv),
            _ => None,
        })
        .map(|tlv| NpduMessage::parse(&tlv[2..]).unwrap())
        .collect();
    // 1. The Network Commissioning Response, unsecured like the request.
    let (rh, rn) = Header::decode_prefix(out[0].npdu).unwrap();
    assert!(!out[0].assume_security && !rh.frame_control.security());
    let NwkCommand::CommissioningResponse(r) =
        NwkCommand::decode_exact(&out[0].npdu[rn..]).unwrap()
    else {
        panic!("not a commissioning response");
    };
    assert_eq!((r.status, r.address), (MacStatus::Success, wanted));
    // 2. The Trust Center's Transport Key: an APS command, NWK-unsecured,
    //    APS-secured with the key-load key (the Basic authorization key
    //    of §4.6.3.2.2.4, never the network key).
    let (kh, kn) = Header::decode_prefix(out[1].npdu).unwrap();
    assert!(!out[1].assume_security);
    assert_eq!(kh.dst, wanted);
    let aps = &out[1].npdu[kn..];
    assert_eq!(aps[0] & 0x03, 0x01, "an APS command frame");
    assert_ne!(aps[0] & 0x20, 0, "APS-secured");
    let aux_control = aps[if aps[0] & 0x80 != 0 { 3 } else { 2 }];
    assert_eq!((aux_control >> 3) & 0x03, 0x03, "key-load key");
    let expected_basic = basic_key::<SoftwareAes>(zvd, &nwk_key);
    assert_ne!(expected_basic, nwk_key);
    assert!(w.nodes[c].2.iter().any(
        |e| matches!(e, Event::Stack(StackEvent::DeviceAuthorized { ieee, .. }) if *ieee == zvd)
    ));
    let child = w.nodes[c].0.stack.nwk.neighbors.by_extended(zvd).unwrap();
    assert_eq!(child.link, Some(1));
    // A secured NPDU is dropped on a provisioning session, but on the
    // authorized session the ZVD's NWK_addr_req (assumed secured) is
    // answered over the tunnel with the link standing in for security.
    w.nodes[c].2.clear();
    let mut apdu = [0u8; 32];
    let aps = ApsHeader::data(
        Addressing::Endpoint(Endpoint(0)),
        ClusterId(0x0000),
        ProfileId::ZDP,
        Endpoint(0),
        1,
    );
    let a = aps.encode_to_slice(&mut apdu).unwrap();
    apdu[a] = 0x33;
    apdu[a + 1..a + 9].copy_from_slice(&zdd_ieee.0.to_le_bytes());
    apdu[a + 9] = 0;
    apdu[a + 10] = 0;
    let header =
        Header::new(FrameType::Data, ShortAddress::COORDINATOR, wanted, 1, 2).with_src_ieee(zvd);
    let mut npdu = [0u8; 64];
    let h = header.encode_to_slice(&mut npdu).unwrap();
    npdu[h..h + a + 11].copy_from_slice(&apdu[..a + 11]);
    let t = NpduMessage {
        assume_security: true,
        npdu: &npdu[..h + a + 11],
    }
    .encode(&mut tlv)
    .unwrap();
    assert!(
        w.nodes[c]
            .0
            .on_tunnel_write(1, SessionKind::ZvdProvisioning, &tlv[..t])
            .is_err()
    );
    w.nodes[c]
        .0
        .on_tunnel_write(1, SessionKind::Authorized, &tlv[..t])
        .unwrap();
    assert!(w.run_until(Duration::from_secs(5), |w| {
        w.nodes[c]
            .2
            .iter()
            .any(|e| matches!(e, Event::DirectTunnel { link: 1, .. }))
    }));
    let rsp = w.nodes[c]
        .2
        .iter()
        .find_map(|e| match e {
            Event::DirectTunnel { tlv, .. } => Some(NpduMessage::parse(&tlv[2..]).unwrap()),
            _ => None,
        })
        .unwrap();
    assert!(rsp.assume_security);
    let (dh, dn) = Header::decode_prefix(rsp.npdu).unwrap();
    assert!(!dh.frame_control.security());
    assert_eq!(dh.dst, wanted);
    // NWK_addr_rsp: APS data, ZDP cluster 0x8000, seq 0x33, SUCCESS, the
    // coordinator's IEEE and address 0x0000.
    let (ah, an) = ApsHeader::decode_prefix(&rsp.npdu[dn..]).unwrap();
    assert_eq!(ah.cluster, Some(ClusterId(0x8000)));
    let zdp = &rsp.npdu[dn + an..];
    assert_eq!(zdp[0], 0x33);
    assert_eq!(zdp[1], 0x00);
    assert_eq!(&zdp[2..10], &zdd_ieee.0.to_le_bytes());
    assert_eq!(&zdp[10..12], &[0x00, 0x00]);
    // A network key update: the broadcast Transport Key with the new
    // network key is declined for the tunnel (§9) and the ZVD gets a
    // Basic authorization key derived from the new key instead.
    w.nodes[c].2.clear();
    w.nodes[c]
        .0
        .stack
        .update_network_key(Key128::from_bytes([0x6b; 16]))
        .unwrap();
    assert!(w.run_until(Duration::from_secs(2), |w| {
        w.nodes[c]
            .2
            .iter()
            .any(|e| matches!(e, Event::DirectTunnelDeclined { link: 1 }))
    }));
    let key_loads = w.nodes[c]
        .2
        .iter()
        .filter_map(|e| match e {
            Event::DirectTunnel { tlv, .. } => Some(NpduMessage::parse(&tlv[2..]).unwrap()),
            _ => None,
        })
        .filter(|m| {
            let Ok((h, n)) = Header::decode_prefix(m.npdu) else {
                return false;
            };
            let aps = &m.npdu[n..];
            h.frame_control.frame_type() == FrameType::Data
                && aps[0] & 0x23 == 0x21
                && (aps[if aps[0] & 0x80 != 0 { 3 } else { 2 }] >> 3) & 0x03 == 0x03
        })
        .count();
    assert_eq!(key_loads, 1, "{:?}", w.nodes[c].2);
    // Closing the tunnel forgets the ZVD.
    w.nodes[c].0.close_tunnel(1);
    assert!(w.nodes[c].0.stack.nwk.neighbors.by_extended(zvd).is_none());
}

/// On a distributed network the ZDD itself hands the ZVD its Basic
/// authorization key under the distributed global link key (ZD 1.1
/// §7.7.4.5).
#[test]
fn zvd_joins_a_distributed_network_through_the_tunnel() {
    use panweave::codec::{Encode, Writer};
    use panweave::nwk::command::{CommissioningRequest, CommissioningType, NwkCommand};
    use panweave::nwk::frame::{FrameType, Header};
    use panweave::nwk::tlv::{
        DeviceCapabilityExtension, FragmentationParameters, SupportedKeyNegotiationMethods, tag,
        write_encapsulation,
    };
    use panweave::types::MacCapability;
    use panweave_direct::tunnel::{NpduMessage, SessionKind};

    let mut w = World {
        medium: VirtualMedium::new(),
        clock: VirtualClock::new(),
        nodes: Vec::new(),
    };
    let zdd_ieee = ExtendedAddress(0x00DD_0000_0000_0003);
    let mut router = Router::distributed(zdd_ieee)
        .build::<SoftwareAes, _, _>(TestRng::seed(9), MemoryStorage::new());
    router.stack.config.trust_center_policy.allow_joins = true;
    router
        .stack
        .config
        .trust_center_policy
        .allow_virtual_devices = true;
    let r = w.add(router);
    w.nodes[r]
        .0
        .stack
        .form_network_with_key(Key128::from_bytes([0x7c; 16]))
        .unwrap();
    assert!(w.run_until(Duration::from_secs(30), |w| {
        w.nodes[r]
            .2
            .iter()
            .any(|e| matches!(e, Event::Stack(StackEvent::NetworkFormed { .. })))
    }));
    assert!(w.nodes[r].0.stack.aps.aib.is_distributed());
    w.nodes[r].0.stack.permit_join_network(180).unwrap();
    w.settle();
    w.nodes[r].2.clear();
    let zvd = ExtendedAddress(0x00AD_0000_0000_0010);
    let wanted = ShortAddress(0x2B7D);
    assert!(w.nodes[r].0.open_tunnel(2, 0x0043, zvd));
    let mut tlvs = [0u8; 48];
    let mut tw = Writer::new(&mut tlvs);
    write_encapsulation(&mut tw, tag::JOINER_ENCAPSULATION, |w| {
        SupportedKeyNegotiationMethods {
            protocols: 0x01,
            secrets: 0x01,
            source: None,
        }
        .write(w)?;
        FragmentationParameters {
            node: wanted,
            options: 0,
            max_incoming_transfer_unit: 128,
        }
        .write(w)?;
        DeviceCapabilityExtension(DeviceCapabilityExtension::ZIGBEE_DIRECT_VIRTUAL_DEVICE).write(w)
    })
    .unwrap();
    let tn = tw.position();
    let header = Header::new(FrameType::Command, ShortAddress(0), wanted, 1, 1)
        .with_src_ieee(zvd)
        .with_dst_ieee(zdd_ieee);
    let zdd_short = w.nodes[r].0.stack.nwk.nib.network_address;
    let header = Header {
        dst: zdd_short,
        ..header
    };
    let cmd = NwkCommand::CommissioningRequest(CommissioningRequest {
        kind: CommissioningType::InitialJoin,
        capability: MacCapability(0)
            .with_rx_on_when_idle(true)
            .with_allocate_address(true),
        tlvs: &tlvs[..tn],
    });
    let mut npdu = [0u8; 120];
    let h = header.encode_to_slice(&mut npdu).unwrap();
    let n = cmd.encode_to_slice(&mut npdu[h..]).unwrap();
    let mut tlv = [0u8; 160];
    let t = NpduMessage {
        assume_security: false,
        npdu: &npdu[..h + n],
    }
    .encode(&mut tlv)
    .unwrap();
    w.nodes[r]
        .0
        .on_tunnel_write(2, SessionKind::ZvdProvisioning, &tlv[..t])
        .unwrap();
    assert!(w.run_until(Duration::from_secs(5), |w| {
        w.nodes[r]
            .2
            .iter()
            .filter(|e| matches!(e, Event::DirectTunnel { link: 2, .. }))
            .count()
            >= 2
    }));
    let out: Vec<NpduMessage<'_>> = w.nodes[r]
        .2
        .iter()
        .filter_map(|e| match e {
            Event::DirectTunnel { tlv, .. } => Some(tlv),
            _ => None,
        })
        .map(|tlv| NpduMessage::parse(&tlv[2..]).unwrap())
        .collect();
    // The second NPDU is the Basic key transport under the key-load key
    // of the distributed global link key; the network key stays home.
    let (kh, kn) = Header::decode_prefix(out[1].npdu).unwrap();
    assert_eq!(kh.dst, wanted);
    let aps = &out[1].npdu[kn..];
    assert_eq!(aps[0] & 0x23, 0x21);
    assert_eq!(
        (aps[if aps[0] & 0x80 != 0 { 3 } else { 2 }] >> 3) & 0x03,
        0x03
    );
    assert!(
        !w.nodes[r]
            .2
            .iter()
            .any(|e| matches!(e, Event::DirectTunnelDeclined { .. }))
    );
    assert_eq!(
        w.nodes[r]
            .0
            .stack
            .nwk
            .neighbors
            .by_extended(zvd)
            .unwrap()
            .link,
        Some(2)
    );
}

/// The Trust Center configures a joined ZDD through the Zigbee Direct
/// Configuration cluster (ZD 1.1 §11.3): interface off and on, the
/// Anonymous Join Timeout, both persistent; and the ZDD finds out that
/// the Trust Center is Zigbee Direct aware (§6.2.3).
#[test]
fn the_trust_center_configures_the_zdd_interface() {
    use panweave::Router;
    use panweave::aps::{Destination, TxOptions};
    use panweave::endpoints;
    use panweave::types::{Endpoint, ProfileId};
    use panweave::zcl::clusters::direct_configuration as dc;
    use panweave::zcl::frame::{Direction, Header};

    let mut w = World {
        medium: VirtualMedium::new(),
        clock: VirtualClock::new(),
        nodes: Vec::new(),
    };
    // A Zigbee Direct aware Trust Center: it carries the configuration
    // client on an endpoint.
    let mut coord = Coordinator::new(ExtendedAddress(0x00DD_0000_0000_0001))
        .build::<SoftwareAes, _, _>(TestRng::seed(21), MemoryStorage::new());
    coord.stack.config.trust_center_policy.allow_joins = true;
    let (d, ep) = endpoints::device(
        Endpoint(1),
        panweave::types::DeviceId(0x0005),
        &[],
        &[dc::ID],
        false,
    )
    .unwrap();
    assert!(d.has_output(dc::ID));
    coord.add_endpoint(d, ep).unwrap();
    let c = w.add(coord);
    let mut zdd = Router::new(ExtendedAddress(0x00DD_0000_0000_0007))
        .build::<SoftwareAes, _, _>(TestRng::seed(22), MemoryStorage::new());
    let (d, ep) = endpoints::on_off_light(Endpoint(3)).unwrap();
    zdd.add_endpoint(d, ep).unwrap();
    zdd.enable_direct_configuration(Endpoint(3)).unwrap();
    assert!(zdd.direct_interface_enabled());
    let z = w.add(zdd);
    w.nodes[c]
        .0
        .stack
        .form_network_with_key(Key128::from_bytes([0x5a; 16]))
        .unwrap();
    assert!(w.run_until(Duration::from_secs(30), |w| {
        w.nodes[c]
            .2
            .iter()
            .any(|e| matches!(e, Event::Stack(StackEvent::NetworkFormed { .. })))
    }));
    w.nodes[c].0.stack.permit_join_network(180).unwrap();
    w.nodes[z].0.steer().unwrap();
    assert!(w.run_until(Duration::from_secs(120), |w| {
        w.nodes[z]
            .2
            .iter()
            .any(|e| matches!(e, Event::Stack(StackEvent::Joined { .. })))
    }));
    w.run_until(Duration::from_secs(5), |_| false);
    // The awareness check finds the client cluster on the Trust Center.
    assert!(w.nodes[z].0.check_direct_aware());
    assert!(w.run_until(Duration::from_secs(10), |w| {
        w.nodes[z].0.direct.trust_center_aware.is_some()
    }));
    assert_eq!(w.nodes[z].0.direct.trust_center_aware, Some(true));
    // An unsecured Configure Zigbee Direct Interface from the Trust
    // Center is NOT_AUTHORIZED; the APS-secured one switches the
    // interface off, persistently.
    let zdd_short = w.nodes[z].0.stack.short_address();
    let send = |w: &mut World, secured: bool, cmd: panweave::types::CommandId, payload: &[u8]| {
        let seq = w.nodes[c].0.stack.zcl.next_seq();
        let header = Header::cluster_specific(seq, cmd, Direction::ToServer);
        w.nodes[c]
            .0
            .stack
            .zcl
            .send(
                Destination::Short {
                    address: zdd_short,
                    endpoint: Endpoint(3),
                },
                ProfileId::HOME_AUTOMATION,
                dc::ID,
                Endpoint(1),
                &header,
                payload,
                TxOptions {
                    security: secured,
                    ..TxOptions::ACKED
                },
            )
            .unwrap();
        w.nodes[c].0.stack.flush();
        seq
    };
    w.nodes[c].2.clear();
    w.nodes[z].2.clear();
    let seq = send(&mut w, false, dc::CMD_CONFIGURE_INTERFACE, &[0]);
    assert!(w.run_until(Duration::from_secs(10), |w| {
        w.nodes[c].2.iter().any(|e| matches!(
            e,
            Event::Stack(StackEvent::ZclResponse(f))
                if f.origin.header.seq == seq && f.payload.first() == Some(&dc::CMD_CONFIGURE_INTERFACE.0)
                    && f.payload.get(1) == Some(&0x7e)
        ))
    }));
    assert!(w.nodes[z].0.direct_interface_enabled());
    let seq = send(&mut w, true, dc::CMD_CONFIGURE_INTERFACE, &[0]);
    assert!(w.run_until(Duration::from_secs(10), |w| {
        w.nodes[c].2.iter().any(|e| {
            matches!(
                e,
                Event::Stack(StackEvent::ZclCommand(f))
                    if f.origin.header.seq == seq
                        && f.origin.header.command == dc::CMD_CONFIGURE_INTERFACE_RESPONSE
                        && dc::InterfaceResponse::parse(&f.payload).is_ok_and(|r| !r.enabled)
            )
        })
    }));
    assert!(!w.nodes[z].0.direct_interface_enabled());
    assert!(w.nodes[z].2.iter().any(|e| matches!(
        e,
        Event::Stack(StackEvent::DirectInterface { enabled: false, .. })
    )));
    // The Anonymous Join Timeout: 120 s, so anonymous provisioning is
    // allowed for two minutes while the network is open.
    let _ = send(
        &mut w,
        true,
        dc::CMD_CONFIGURE_ANONYMOUS_JOIN_TIMEOUT,
        &[120, 0, 0],
    );
    assert!(w.run_until(Duration::from_secs(10), |w| {
        w.nodes[z].2.iter().any(|e| {
            matches!(
                e,
                Event::Stack(StackEvent::DirectAnonymousJoinTimeout { seconds: 120, .. })
            )
        })
    }));
    assert!(w.nodes[z].0.anonymous_join_allowed());
    w.run_until(Duration::from_secs(130), |_| false);
    assert!(!w.nodes[z].0.anonymous_join_allowed());
    // Both settings survive a restart; the countdown restarts.
    let storage = w.nodes[z].0.stack.storage.clone();
    let mut again = Router::new(ExtendedAddress(0x00DD_0000_0000_0007))
        .build::<SoftwareAes, _, _>(TestRng::seed(23), storage);
    again.restore_direct_config().unwrap();
    assert!(!again.direct_interface_enabled());
    assert_eq!(again.direct.anonymous_join_timeout, 120);
    assert!(again.direct.anonymous_join_until.is_some());
}

/// An out-of-band join with a provisional Trust Center link key
/// (ZD 1.1 §7.7.2.7.4): the ZDD updates the key once on the network; when
/// the Trust Center is out of reach it stays on the network and retries
/// until the update succeeds. The Admin key hand-off of §6.3.2.1: the
/// provisioned key when there is one, the key derived from the active
/// TCLK otherwise, persisted until a factory reset.
#[test]
fn an_out_of_band_join_updates_a_provisional_link_key_when_the_trust_center_answers() {
    use panweave::runtime::AdoptParams;
    use panweave::types::KeySequenceNumber;
    use panweave_direct::commissioning::LinkKey;

    let mut w = World {
        medium: VirtualMedium::new(),
        clock: VirtualClock::new(),
        nodes: Vec::new(),
    };
    let channel = Channel::new_2_4ghz(15).unwrap();
    let mask = ChannelMask::EMPTY.with(channel);
    let nwk_key = Key128::from_bytes([0x5a; 16]);
    let epid = ExtendedAddress(0x00EE_0000_0000_0001);
    let tc = ExtendedAddress(0x00DD_0000_0000_0001);
    let zvd = ExtendedAddress(0x00AA_0000_0000_0001);

    // The ZDD is alone on the air when it is provisioned.
    let router = Router::new(ExtendedAddress(0x00DD_0000_0000_0003))
        .build::<SoftwareAes, _, _>(TestRng::seed(3), MemoryStorage::new());
    let r = w.add(router);
    let mut zvd_r = Commissioning::new(Level::Provisioning, false);
    let mut buf = [0u8; 160];
    let n = JoinNetwork {
        method: JoiningMethod::OutOfBand,
        extended_pan_id: Some(epid),
        pan_id: Some(PanId(0x1A62)),
        channels: Some(mask),
        network_key: Some(nwk_key.clone()),
        link_key: Some(LinkKey {
            unique: false,
            provisional: true,
            key: Key128::WELL_KNOWN_GLOBAL_TCLK,
        }),
        nwk_address: Some(ShortAddress(0x3344)),
        trust_center: Some(tc),
        update_id: Some(0),
        key_sequence: Some(0),
        admin_key: None,
    }
    .encode(&mut buf)
    .unwrap();
    assert_eq!(
        zvd_r.write(&mut w.nodes[r].0, Characteristic::JoinNetwork, &buf[..n]),
        Access::Ok
    );
    assert!(w.run_until(Duration::from_secs(10), |w| {
        direct_done(w, r, Domain::JoinNetwork) == Some(0)
    }));
    assert!(w.nodes[r].0.direct_tclk_update_pending());
    assert!(w.nodes[r].0.stack.trust_center_link_key_is_provisional());
    // No Admin key was provisioned: it derives from the (provisional)
    // link key for now.
    let derived_provisional = w.nodes[r].0.admin_key_for(zvd).unwrap();
    assert_eq!(
        derived_provisional,
        panweave_direct::auth::admin_key::<SoftwareAes>(zvd, &Key128::WELL_KNOWN_GLOBAL_TCLK)
    );
    // The first attempt fails for want of a Trust Center; the ZDD stays
    // on the network and keeps the update owed.
    assert!(w.run_until(Duration::from_secs(60), |w| {
        w.nodes[r]
            .2
            .iter()
            .any(|e| matches!(e, Event::Stack(StackEvent::LinkKeyUpdateFailed)))
    }));
    assert!(w.nodes[r].0.stack.is_operating());
    assert!(w.nodes[r].0.direct_tclk_update_pending());
    assert!(
        !w.nodes[r]
            .2
            .iter()
            .any(|e| matches!(e, Event::Stack(StackEvent::Left { .. })))
    );

    // The Trust Center comes up with the same network parameters; the
    // commissioner registered the ZDD there with its provisional key
    // (R23.2 §4.4.1.2 step 3: the Trust Center needs a key-pair entry
    // for the source of an APS-secured frame).
    let mut coord =
        Coordinator::new(tc).build::<SoftwareAes, _, _>(TestRng::seed(1), MemoryStorage::new());
    coord.stack.config.trust_center_policy.allow_joins = true;
    coord.stack.install_link_key(
        ExtendedAddress(0x00DD_0000_0000_0003),
        Key128::WELL_KNOWN_GLOBAL_TCLK,
        panweave::security::material::LinkKeyKind::Global,
        true,
    );
    let c = w.add(coord);
    w.nodes[c]
        .0
        .stack
        .adopt_network(&AdoptParams {
            extended_pan_id: epid,
            pan_id: PanId(0x1A62),
            channel,
            network_address: None,
            key: nwk_key.clone(),
            key_sequence: KeySequenceNumber(0),
            update_id: 0,
            trust_center: tc,
        })
        .unwrap();
    w.nodes[r].2.clear();
    // The retry finds it: the link key is updated and verified.
    assert!(w.run_until(Duration::from_secs(180), |w| {
        w.nodes[r]
            .2
            .iter()
            .any(|e| matches!(e, Event::Stack(StackEvent::LinkKeyUpdated)))
    }));
    assert!(!w.nodes[r].0.direct_tclk_update_pending());
    assert!(!w.nodes[r].0.stack.trust_center_link_key_is_provisional());
    // The derived Admin key follows the active TCLK.
    let derived = w.nodes[r].0.admin_key_for(zvd).unwrap();
    assert_ne!(derived, derived_provisional);
    let tclk = w.nodes[r]
        .0
        .stack
        .aps
        .security
        .entry(tc)
        .unwrap()
        .key
        .clone();
    assert_eq!(
        derived,
        panweave_direct::auth::admin_key::<SoftwareAes>(zvd, &tclk)
    );

    // A provisioned Admin key wins and survives a restart; a factory
    // reset forgets it.
    let admin = Key128::from_bytes([0x77; 16]);
    let mut other: N = Router::new(ExtendedAddress(0x00DD_0000_0000_0004))
        .build::<SoftwareAes, _, _>(TestRng::seed(4), MemoryStorage::new());
    let mut zvd_o = Commissioning::new(Level::Provisioning, false);
    let n = JoinNetwork {
        method: JoiningMethod::OutOfBand,
        extended_pan_id: Some(epid),
        pan_id: Some(PanId(0x1A62)),
        channels: Some(mask),
        network_key: Some(nwk_key.clone()),
        link_key: None,
        nwk_address: Some(ShortAddress(0x3355)),
        trust_center: Some(tc),
        update_id: Some(0),
        key_sequence: Some(0),
        admin_key: Some(admin.clone()),
    }
    .encode(&mut buf)
    .unwrap();
    assert_eq!(
        zvd_o.write(&mut other, Characteristic::JoinNetwork, &buf[..n]),
        Access::Ok
    );
    assert_eq!(other.admin_key_for(zvd), Some(admin.clone()));
    let storage = other.stack.storage.clone();
    let mut again = Router::new(ExtendedAddress(0x00DD_0000_0000_0004))
        .build::<SoftwareAes, _, _>(TestRng::seed(5), storage);
    again.restore_direct_admin_key().unwrap();
    assert_eq!(again.direct.admin_key, Some(admin));
    other.factory_reset().unwrap();
    assert_eq!(other.admin_key_for(zvd), None);
    let mut fresh = Router::new(ExtendedAddress(0x00DD_0000_0000_0004))
        .build::<SoftwareAes, _, _>(TestRng::seed(6), other.stack.storage.clone());
    fresh.restore_direct_admin_key().unwrap();
    assert_eq!(fresh.direct.admin_key, None);
}
