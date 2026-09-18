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

/// The ZVD chooses the security model with the Trust Center Address TLV
/// (ZD 1.1 §7.7.2.5, Table 36): a coordinator-capable ZDD forms a
/// distributed network on request and a router joins it by association;
/// a router-only ZDD refuses to form a centralized one.
#[test]
fn the_zvd_chooses_the_security_model_of_a_formed_network() {
    use panweave_direct::commissioning::STATUS_FAILURE;

    let mut w = World {
        medium: VirtualMedium::new(),
        clock: VirtualClock::new(),
        nodes: Vec::new(),
    };
    let channel = Channel::new_2_4ghz(20).unwrap();
    let mask = ChannelMask::EMPTY.with(channel);
    let mut buf = [0u8; 128];

    // A router-only ZDD cannot become a Trust Center.
    let router = Router::new(ExtendedAddress(0x00DD_0000_0000_0002))
        .build::<SoftwareAes, _, _>(TestRng::seed(2), MemoryStorage::new());
    let r = w.add(router);
    let mut zvd_r = Commissioning::new(Level::Provisioning, false);
    let n = FormNetwork {
        distributed: false,
        channels: Some(mask),
        ..FormNetwork::default()
    }
    .encode(&mut buf)
    .unwrap();
    assert_eq!(
        zvd_r.write(&mut w.nodes[r].0, Characteristic::FormNetwork, &buf[..n]),
        Access::Ok
    );
    let (_, code) = decode_status(&zvd_r.next_notification().unwrap()).unwrap();
    assert_eq!(code, Some((Domain::FormNetwork as u8, STATUS_FAILURE)));
    assert!(!w.nodes[r].0.stack.is_operating());

    // A coordinator-capable ZDD forms the distributed network the ZVD
    // asks for: no Trust Center, a stochastic address.
    let coord = Coordinator::new(ExtendedAddress(0x00DD_0000_0000_0001))
        .build::<SoftwareAes, _, _>(TestRng::seed(1), MemoryStorage::new());
    let c = w.add(coord);
    let mut zvd_c = Commissioning::new(Level::Provisioning, false);
    let n = FormNetwork {
        distributed: true,
        pan_id: Some(PanId(0x2B73)),
        channels: Some(mask),
        network_key: Some(Key128::from_bytes([0x4c; 16])),
        ..FormNetwork::default()
    }
    .encode(&mut buf)
    .unwrap();
    assert_eq!(
        zvd_c.write(&mut w.nodes[c].0, Characteristic::FormNetwork, &buf[..n]),
        Access::Ok
    );
    assert!(w.run_until(Duration::from_secs(30), |w| {
        direct_done(w, c, Domain::FormNetwork).is_some()
    }));
    let note = report(&mut w, c, &mut zvd_c, Domain::FormNetwork);
    let (rep, code) = decode_status(&note).unwrap();
    assert!(code.is_none());
    let rep = rep.unwrap();
    assert_eq!(rep.status.joined, JoinedStatus::Commissioned);
    assert!(!rep.status.centralized);
    let info = rep.network.unwrap();
    assert_eq!(info.trust_center, ExtendedAddress::BROADCAST);
    assert_ne!(info.nwk_address, ShortAddress(0));
    assert!(w.nodes[c].0.stack.config.distributed);
    // No admin access without a provisioned Admin key on a distributed
    // network (§7.7.2.7.1).
    assert_eq!(
        w.nodes[c]
            .0
            .admin_key_for(ExtendedAddress(0x00AA_0000_0000_0001)),
        None
    );
    let epid = info.extended_pan_id;

    // Opened by the ZVD, the router ZDD joins by association and gets
    // the distributed global link key.
    let mut admin_c = Commissioning::new(Level::Admin, true);
    assert_eq!(
        admin_c.write(&mut w.nodes[c].0, Characteristic::PermitJoining, &[120]),
        Access::Ok
    );
    let _ = admin_c.next_notification();
    w.settle();
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
        zvd_r.write(&mut w.nodes[r].0, Characteristic::JoinNetwork, &buf[..n]),
        Access::Ok
    );
    assert!(
        w.run_until(Duration::from_secs(120), |w| direct_done(
            w,
            r,
            Domain::JoinNetwork
        )
        .is_some()),
        "{:?}",
        w.nodes[r].2
    );
    let note = report(&mut w, r, &mut zvd_r, Domain::JoinNetwork);
    let (rep, code) = decode_status(&note).unwrap();
    assert!(code.is_none(), "{code:?}");
    let rep = rep.unwrap();
    assert!(!rep.status.centralized);
    let info = rep.network.unwrap();
    assert_eq!(info.extended_pan_id, epid);
    assert_eq!(info.trust_center, ExtendedAddress::BROADCAST);
    assert!(w.nodes[r].0.stack.is_operating());
}

/// A ZVD operating as Trust Center (ZD 1.1 §7.7.4.4): it commissions the
/// ZDD out of band as the first router with its own EUI-64 as Trust
/// Center, then re-establishes its connectivity through the tunnel with
/// a Network Commissioning Request of type Establish Trusted Link; the
/// ZDD answers with address 0x0000 and reaches the Trust Center over the
/// link from then on. Anyone else asking is refused.
#[test]
fn a_zvd_acting_as_trust_center_attaches_behind_the_trusted_link() {
    use panweave::codec::{Decode, Encode, Writer};
    use panweave::nwk::command::{CommissioningRequest, CommissioningType, NwkCommand};
    use panweave::nwk::frame::{FrameType, Header};
    use panweave::nwk::tlv::{
        DeviceCapabilityExtension, FragmentationParameters, SupportedKeyNegotiationMethods, tag,
        write_encapsulation,
    };
    use panweave::types::{MacCapability, MacStatus};
    use panweave_direct::commissioning::LinkKey;
    use panweave_direct::tunnel::{NpduMessage, SessionKind};

    fn joiner_tlvs() -> Vec<u8> {
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
                node: ShortAddress::COORDINATOR,
                options: 0,
                max_incoming_transfer_unit: 128,
            }
            .write(w)?;
            DeviceCapabilityExtension(DeviceCapabilityExtension::ZIGBEE_DIRECT_VIRTUAL_DEVICE)
                .write(w)
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
    let channel = Channel::new_2_4ghz(25).unwrap();
    let mask = ChannelMask::EMPTY.with(channel);
    let zvd = ExtendedAddress(0x00AA_0000_0000_0001);
    let zdd_ieee = ExtendedAddress(0x00DD_0000_0000_0003);
    let zdd_short = ShortAddress(0x3344);
    let router =
        Router::new(zdd_ieee).build::<SoftwareAes, _, _>(TestRng::seed(3), MemoryStorage::new());
    let r = w.add(router);
    let mut zvd_r = Commissioning::new(Level::Provisioning, false);
    let mut buf = [0u8; 160];
    let n = JoinNetwork {
        method: JoiningMethod::OutOfBand,
        extended_pan_id: Some(ExtendedAddress(0x00EE_0000_0000_0002)),
        pan_id: Some(PanId(0x3C84)),
        channels: Some(mask),
        network_key: Some(Key128::from_bytes([0x5a; 16])),
        link_key: Some(LinkKey {
            unique: true,
            provisional: false,
            key: Key128::from_bytes([0x11; 16]),
        }),
        nwk_address: Some(zdd_short),
        trust_center: Some(zvd),
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
    // A verified unique key with the ZVD Trust Center: nothing to update.
    assert!(!w.nodes[r].0.direct_tclk_update_pending());
    w.settle();
    w.nodes[r].2.clear();

    // The tunnel opens on the authorized session; the ZVD sends the
    // Establish Trusted Link request, NWK-secured over the link.
    assert!(w.nodes[r].0.open_tunnel(2, 0x0043, zvd));
    let tlvs = joiner_tlvs();
    let capability = MacCapability(0)
        .with_rx_on_when_idle(true)
        .with_full_function_device(true);
    let request = |seq: u8, src: ShortAddress, src_ieee: ExtendedAddress| {
        let header = Header::new(FrameType::Command, zdd_short, src, 1, seq)
            .with_src_ieee(src_ieee)
            .with_dst_ieee(zdd_ieee);
        let cmd = NwkCommand::CommissioningRequest(CommissioningRequest {
            kind: CommissioningType::EstablishTrustedLink,
            capability,
            tlvs: &tlvs,
        });
        let mut npdu = [0u8; 120];
        let h = header.encode_to_slice(&mut npdu).unwrap();
        let n = cmd.encode_to_slice(&mut npdu[h..]).unwrap();
        npdu[..h + n].to_vec()
    };
    let write = |w: &mut World, npdu: &[u8], secured: bool| {
        let mut tlv = [0u8; 160];
        let t = NpduMessage {
            assume_security: secured,
            npdu,
        }
        .encode(&mut tlv)
        .unwrap();
        w.nodes[r]
            .0
            .on_tunnel_write(2, SessionKind::Authorized, &tlv[..t])
            .unwrap();
        w.settle();
    };
    let responses = |w: &World| -> Vec<(MacStatus, ShortAddress, bool)> {
        w.nodes[r]
            .2
            .iter()
            .filter_map(|e| match e {
                Event::DirectTunnel { link: 2, tlv } => {
                    Some(NpduMessage::parse(&tlv[2..]).unwrap())
                }
                _ => None,
            })
            .filter_map(|m| {
                let (_, n) = Header::decode_prefix(m.npdu).ok()?;
                match NwkCommand::decode_exact(&m.npdu[n..]).ok()? {
                    NwkCommand::CommissioningResponse(r) => {
                        Some((r.status, r.address, m.assume_security))
                    }
                    _ => None,
                }
            })
            .collect()
    };
    // Unsecured: dropped. From another device: refused. Not as 0x0000:
    // refused.
    write(&mut w, &request(1, ShortAddress::COORDINATOR, zvd), false);
    assert!(responses(&w).is_empty());

    let other = ExtendedAddress(0x00AA_0000_0000_0002);
    write(&mut w, &request(2, ShortAddress::COORDINATOR, other), true);
    write(&mut w, &request(3, ShortAddress(0x0001), zvd), true);
    assert_eq!(
        responses(&w),
        vec![
            (MacStatus::PanAccessDenied, ShortAddress::COORDINATOR, true),
            (MacStatus::PanAccessDenied, ShortAddress(0x0001), true),
        ]
    );
    assert!(w.nodes[r].0.stack.nwk.neighbors.by_extended(zvd).is_none());
    w.nodes[r].2.clear();
    // The Trust Center itself: success at 0x0000, reachable over the link.
    write(&mut w, &request(4, ShortAddress::COORDINATOR, zvd), true);
    assert_eq!(
        responses(&w),
        vec![(MacStatus::Success, ShortAddress::COORDINATOR, true)]
    );
    assert!(w.nodes[r].2.iter().any(|e| matches!(
        e,
        Event::Stack(StackEvent::TrustCenterLinked { ieee, link: 2 }) if *ieee == zvd
    )));
    let n = w.nodes[r].0.stack.nwk.neighbors.by_extended(zvd).unwrap();
    assert_eq!(
        (n.short, n.link, n.is_router()),
        (ShortAddress::COORDINATOR, Some(2), true)
    );
    assert!(
        !w.nodes[r]
            .2
            .iter()
            .any(|e| matches!(e, Event::Stack(StackEvent::DeviceAnnounce { .. })))
    );
    w.nodes[r].2.clear();
    // A ZDP request to the Trust Center leaves through the tunnel,
    // NWK-secured, and the link is not aged out for want of Link Status.
    w.nodes[r]
        .0
        .stack
        .zdo
        .request(
            ShortAddress::COORDINATOR,
            panweave::zdo::zdp::cluster::NODE_DESC_REQ,
            &[0, 0],
        )
        .unwrap();
    w.run_until(Duration::from_secs(120), |_| false);
    let out: Vec<(ShortAddress, bool)> = w.nodes[r]
        .2
        .iter()
        .filter_map(|e| match e {
            Event::DirectTunnel { link: 2, tlv } => Some(NpduMessage::parse(&tlv[2..]).unwrap()),
            _ => None,
        })
        .filter_map(|m| {
            let (h, _) = Header::decode_prefix(m.npdu).ok()?;
            (h.frame_control.frame_type() == FrameType::Data).then_some((h.dst, m.assume_security))
        })
        .collect();
    // (APS retries the unanswered request.)
    assert!(!out.is_empty());
    assert!(out.iter().all(|o| *o == (ShortAddress::COORDINATOR, true)));
    let n = w.nodes[r].0.stack.nwk.neighbors.by_extended(zvd).unwrap();
    assert_eq!(n.outgoing_cost, 1);
    // Closing the tunnel forgets the Trust Center's link.
    w.nodes[r].0.close_tunnel(2);
    assert!(w.nodes[r].0.stack.nwk.neighbors.by_extended(zvd).is_none());
}

/// A ZVD rejoining through the ZDD (ZD 1.1 §7.7.4.6): after its first
/// join and a closed tunnel, a secure rejoin (Network Commissioning
/// Request of type Rejoin, NWK-secured over the authorized session) is
/// accepted without any key transport; a Trust Center rejoin (unsecured,
/// over the provisioning session, after a missed key rotation) gets a
/// fresh Basic authorization key under the key-load key.
#[test]
fn a_zvd_rejoins_through_the_tunnel() {
    use panweave::codec::{Decode, Encode, Writer};
    use panweave::nwk::command::{CommissioningRequest, CommissioningType, NwkCommand};
    use panweave::nwk::frame::{FrameType, Header};
    use panweave::nwk::tlv::{
        DeviceCapabilityExtension, FragmentationParameters, SupportedKeyNegotiationMethods, tag,
        write_encapsulation,
    };
    use panweave::types::{MacCapability, MacStatus};
    use panweave_direct::tunnel::{NpduMessage, SessionKind};

    fn joiner_tlvs() -> Vec<u8> {
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
            DeviceCapabilityExtension(DeviceCapabilityExtension::ZIGBEE_DIRECT_VIRTUAL_DEVICE)
                .write(w)
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
    w.settle();
    let zvd = ExtendedAddress(0x00AD_0000_0000_0009);
    let wanted = ShortAddress(0x4E21);
    let tlvs = joiner_tlvs();
    let capability = MacCapability(0)
        .with_rx_on_when_idle(true)
        .with_allocate_address(true);
    let request = |seq: u8, kind: CommissioningType| {
        let header = Header::new(
            FrameType::Command,
            ShortAddress::COORDINATOR,
            wanted,
            1,
            seq,
        )
        .with_src_ieee(zvd)
        .with_dst_ieee(zdd_ieee);
        let cmd = NwkCommand::CommissioningRequest(CommissioningRequest {
            kind,
            capability,
            tlvs: &tlvs,
        });
        let mut npdu = [0u8; 120];
        let h = header.encode_to_slice(&mut npdu).unwrap();
        let n = cmd.encode_to_slice(&mut npdu[h..]).unwrap();
        npdu[..h + n].to_vec()
    };
    let write = |w: &mut World, npdu: &[u8], secured: bool, session: SessionKind| {
        let mut tlv = [0u8; 160];
        let t = NpduMessage {
            assume_security: secured,
            npdu,
        }
        .encode(&mut tlv)
        .unwrap();
        w.nodes[c].0.on_tunnel_write(1, session, &tlv[..t]).unwrap();
        w.run_until(Duration::from_secs(5), |_| false);
    };
    // Everything the ZDD tunnelled: commissioning responses and
    // key-load-secured APS commands (Transport Key with a Basic key).
    let tunnelled = |w: &World| -> (Vec<(MacStatus, ShortAddress)>, usize) {
        let mut responses = Vec::new();
        let mut key_loads = 0;
        for e in &w.nodes[c].2 {
            let Event::DirectTunnel { link: 1, tlv } = e else {
                continue;
            };
            let m = NpduMessage::parse(&tlv[2..]).unwrap();
            let Ok((h, n)) = Header::decode_prefix(m.npdu) else {
                continue;
            };
            let body = &m.npdu[n..];
            match h.frame_control.frame_type() {
                FrameType::Command => {
                    if let Ok(NwkCommand::CommissioningResponse(r)) = NwkCommand::decode_exact(body)
                    {
                        responses.push((r.status, r.address));
                    }
                }
                FrameType::Data
                    if body[0] & 0x23 == 0x21
                        && (body[if body[0] & 0x80 != 0 { 3 } else { 2 }] >> 3) & 0x03 == 0x03 =>
                {
                    key_loads += 1;
                }
                _ => {}
            }
        }
        (responses, key_loads)
    };

    // First join, then the tunnel closes: the ZDD forgets the ZVD, the
    // Trust Center keeps its key-pair entry.
    assert!(w.nodes[c].0.open_tunnel(1, 0x0042, zvd));
    w.nodes[c].2.clear();
    write(
        &mut w,
        &request(1, CommissioningType::InitialJoin),
        false,
        SessionKind::ZvdProvisioning,
    );
    assert_eq!(tunnelled(&w), (vec![(MacStatus::Success, wanted)], 1));
    w.nodes[c].0.close_tunnel(1);
    assert!(w.nodes[c].0.stack.nwk.neighbors.by_extended(zvd).is_none());
    assert!(w.nodes[c].0.stack.aps.security.entry(zvd).is_some());

    // Secure rejoin on a new authorized session: accepted at the same
    // address, no key transported, the ZVD is a child behind the link.
    assert!(w.nodes[c].0.open_tunnel(1, 0x0043, zvd));
    w.nodes[c].2.clear();
    write(
        &mut w,
        &request(2, CommissioningType::Rejoin),
        true,
        SessionKind::Authorized,
    );
    assert_eq!(tunnelled(&w), (vec![(MacStatus::Success, wanted)], 0));
    assert!(w.nodes[c].2.iter().any(
        |e| matches!(e, Event::Stack(StackEvent::DeviceAuthorized { ieee, .. }) if *ieee == zvd)
    ));
    let child = w.nodes[c].0.stack.nwk.neighbors.by_extended(zvd).unwrap();
    assert_eq!((child.short, child.link), (wanted, Some(1)));
    assert!(child.relationship.is_child());
    w.nodes[c].0.close_tunnel(1);

    // Trust Center rejoin after a missed key rotation: unsecured over the
    // provisioning session; the answer is a Basic key derived from the
    // current network key, never the network key.
    w.nodes[c]
        .0
        .stack
        .update_network_key(Key128::from_bytes([0x6b; 16]))
        .unwrap();
    w.run_until(Duration::from_secs(20), |_| false);
    assert!(w.nodes[c].0.open_tunnel(1, 0x0044, zvd));
    w.nodes[c].2.clear();
    write(
        &mut w,
        &request(3, CommissioningType::Rejoin),
        false,
        SessionKind::ZvdProvisioning,
    );
    assert_eq!(tunnelled(&w), (vec![(MacStatus::Success, wanted)], 1));
    assert!(w.nodes[c].2.iter().any(
        |e| matches!(e, Event::Stack(StackEvent::DeviceAuthorized { ieee, .. }) if *ieee == zvd)
    ));
    assert!(
        !w.nodes[c]
            .2
            .iter()
            .any(|e| matches!(e, Event::DirectTunnelDeclined { .. }))
    );
}

/// A ZDD on a legacy network (ZD 1.1 §10, class II): the Trust Center
/// predates Zigbee Direct and tunnels the network key to the joining
/// ZVD; the ZDD swallows it, sends a global ephemeral authorization key
/// instead, lets only the ZVD's exchange with the Trust Center through
/// (§10.1), watches for the Trust Center's key-load and data-key secured
/// messages and only then hands the ZVD its Basic key on the Trust
/// Center's behalf. A ZVD that never authenticates is dropped after
/// `apsSecurityTimeOutPeriod`.
#[test]
fn a_zdd_on_a_legacy_network_authorizes_the_zvd_itself() {
    use panweave::aps::command::KeyDescriptor;
    use panweave::aps::layer::{
        ApsAction, ApsConfig, ApsEvent, DeviceState, NwkView, TransportedKey,
    };
    use panweave::aps::{Aps, command::RequestKeyType};
    use panweave::codec::{Encode, Writer};
    use panweave::nwk::command::{CommissioningRequest, CommissioningType, NwkCommand};
    use panweave::nwk::frame::{FrameType, Header};
    use panweave::nwk::tlv::{
        DeviceCapabilityExtension, FragmentationParameters, SupportedKeyNegotiationMethods, tag,
        write_encapsulation,
    };
    use panweave::security::authorization::basic_key;
    use panweave::security::material::{LinkKeyEntry, LinkKeyKind};
    use panweave::types::{KeyType, MacCapability, NwkStatus};
    use panweave_direct::legacy::Phase;
    use panweave_direct::tunnel::{NpduMessage, SessionKind, TunnelError};

    /// What the test-side ZVD knows of the network's addresses.
    struct View {
        tc: ExtendedAddress,
        zdd: (ExtendedAddress, ShortAddress),
    }
    impl NwkView for View {
        fn ieee_of(&self, short: ShortAddress) -> Option<ExtendedAddress> {
            if short == ShortAddress::COORDINATOR {
                Some(self.tc)
            } else if short == self.zdd.1 {
                Some(self.zdd.0)
            } else {
                None
            }
        }
        fn short_of(&self, ieee: ExtendedAddress) -> Option<ShortAddress> {
            if ieee == self.tc {
                Some(ShortAddress::COORDINATOR)
            } else if ieee == self.zdd.0 {
                Some(self.zdd.1)
            } else {
                None
            }
        }
        fn unauthenticated_child(&self, _ieee: ExtendedAddress) -> Option<ShortAddress> {
            None
        }
    }

    fn joiner_tlvs(node: ShortAddress) -> Vec<u8> {
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
                node,
                options: 0,
                max_incoming_transfer_unit: 128,
            }
            .write(w)?;
            DeviceCapabilityExtension(DeviceCapabilityExtension::ZIGBEE_DIRECT_VIRTUAL_DEVICE)
                .write(w)
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
    let tc_ieee = ExtendedAddress(0x00DD_0000_0000_0001);
    let zdd_ieee = ExtendedAddress(0x00DD_0000_0000_0002);
    let nwk_key = Key128::from_bytes([0x5a; 16]);
    // A Trust Center from before Zigbee Direct: no Configuration client,
    // network keys for everyone.
    let mut coord = Coordinator::new(tc_ieee)
        .build::<SoftwareAes, _, _>(TestRng::seed(7), MemoryStorage::new());
    coord.stack.config.trust_center_policy.allow_joins = true;
    coord.stack.config.zigbee_direct_aware = false;
    let c = w.add(coord);
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
    w.nodes[c].0.stack.permit_join_network(254).unwrap();
    // The ZDD router joins and learns that its Trust Center is not
    // Zigbee Direct aware (§6.2.3).
    let router =
        Router::new(zdd_ieee).build::<SoftwareAes, _, _>(TestRng::seed(8), MemoryStorage::new());
    let r = w.add(router);
    w.nodes[r].0.steer().unwrap();
    assert!(w.run_until(Duration::from_secs(120), |w| {
        w.nodes[r]
            .2
            .iter()
            .any(|e| matches!(e, Event::Stack(StackEvent::Joined { .. })))
    }));
    w.run_until(Duration::from_secs(5), |_| false);
    assert!(w.nodes[r].0.check_direct_aware());
    assert!(w.run_until(Duration::from_secs(10), |w| {
        w.nodes[r].0.direct.trust_center_aware.is_some()
    }));
    assert_eq!(w.nodes[r].0.direct.trust_center_aware, Some(false));
    let zdd_short = w.nodes[r].0.stack.short_address();
    w.nodes[c].2.clear();
    w.nodes[r].2.clear();

    // The ZVD: a BLE peer with an APS layer of its own, holding the
    // well-known key for the Trust Center (and for the ZDD, which
    // secures the authorization keys it sends with it).
    let zvd_ieee = ExtendedAddress(0x00AD_0000_0000_0009);
    let zvd_short = ShortAddress(0x4E21);
    let view = View {
        tc: tc_ieee,
        zdd: (zdd_ieee, zdd_short),
    };
    let mut zvd: Aps<SoftwareAes, 4, 4, 4, 4> = Aps::new(zvd_ieee, ApsConfig::default());
    zvd.aib.trust_center_address = tc_ieee;
    for partner in [tc_ieee, zdd_ieee] {
        zvd.install_link_key(LinkKeyEntry::provisional(
            partner,
            Key128::WELL_KNOWN_GLOBAL_TCLK,
            LinkKeyKind::Global,
        ))
        .unwrap();
    }
    zvd.set_network_state(zvd_short, DeviceState::JoinedAuthorized);
    assert!(w.nodes[r].0.open_tunnel(1, 0x0042, zvd_ieee));

    // The ZVD's NPDUs: a NWK data frame around an APS frame.
    let wrap = |dst: ShortAddress, seq: u8, aps: &[u8]| -> Vec<u8> {
        let header = Header::new(FrameType::Data, dst, zvd_short, 30, seq).with_src_ieee(zvd_ieee);
        let mut npdu = [0u8; 160];
        let h = header.encode_to_slice(&mut npdu).unwrap();
        npdu[h..h + aps.len()].copy_from_slice(aps);
        npdu[..h + aps.len()].to_vec()
    };
    let write = |w: &mut World, npdu: &[u8], secured: bool| -> Result<(), TunnelError> {
        let mut tlv = [0u8; 200];
        let t = NpduMessage {
            assume_security: secured,
            npdu,
        }
        .encode(&mut tlv)
        .unwrap();
        let res = w.nodes[r]
            .0
            .on_tunnel_write(1, SessionKind::ZvdProvisioning, &tlv[..t]);
        w.run_until(Duration::from_secs(3), |_| false);
        res
    };
    // Everything the ZDD tunnelled since the last call, fed to the ZVD's
    // APS layer; the ZVD's own output goes back through the tunnel.
    let mut fed = 0usize;
    let mut zvd_seq = 10u8;
    let mut pump = |w: &mut World, zvd: &mut Aps<SoftwareAes, 4, 4, 4, 4>| -> Vec<ApsEvent> {
        let mut events = Vec::new();
        loop {
            while let Some(a) = zvd.next_action() {
                match a {
                    ApsAction::NwkData {
                        handle,
                        dst,
                        secure,
                        frame,
                        ..
                    } => {
                        zvd_seq = zvd_seq.wrapping_add(1);
                        let _ = write(w, &wrap(dst, zvd_seq, &frame), secure);
                        zvd.on_nwk_data_confirm(handle, NwkStatus::Success);
                    }
                    ApsAction::CounterReservation {
                        partner,
                        reservation,
                    } => zvd.commit_counter_reservation(partner, reservation),
                    ApsAction::Persist(_) => {}
                }
            }
            let npdus: Vec<(Vec<u8>, bool)> = w.nodes[r]
                .2
                .iter()
                .filter_map(|e| match e {
                    Event::DirectTunnel { link: 1, tlv } => {
                        let m = NpduMessage::parse(&tlv[2..]).unwrap();
                        Some((m.npdu.to_vec(), m.assume_security))
                    }
                    _ => None,
                })
                .skip(fed)
                .collect();
            if npdus.is_empty() {
                break;
            }
            fed += npdus.len();
            for (npdu, secured) in npdus {
                let (h, n) = Header::decode_prefix(&npdu).unwrap();
                if h.frame_control.frame_type() != FrameType::Data {
                    continue;
                }
                let mut aps = npdu[n..].to_vec();
                let _ = zvd.on_nwk_data(&mut aps, h.src, h.dst, h.src_ieee, secured, 255, &view);
                while let Some(e) = zvd.next_event() {
                    events.push(e);
                }
            }
        }
        events
    };

    // 1. Initial join over the provisioning session.
    let tlvs = joiner_tlvs(zvd_short);
    let header = Header::new(FrameType::Command, zdd_short, zvd_short, 1, 1)
        .with_src_ieee(zvd_ieee)
        .with_dst_ieee(zdd_ieee);
    let cmd = NwkCommand::CommissioningRequest(CommissioningRequest {
        kind: CommissioningType::InitialJoin,
        capability: MacCapability(0)
            .with_rx_on_when_idle(true)
            .with_allocate_address(true),
        tlvs: &tlvs,
    });
    let mut npdu = [0u8; 120];
    let h = header.encode_to_slice(&mut npdu).unwrap();
    let n = cmd.encode_to_slice(&mut npdu[h..]).unwrap();
    write(&mut w, &npdu[..h + n], false).unwrap();
    // The Trust Center tunnelled the network key; the ZVD got a global
    // ephemeral authorization key instead and nothing else.
    let events = pump(&mut w, &mut zvd);
    assert!(
        events.iter().any(|e| matches!(
            e,
            ApsEvent::TransportKey {
                key: TransportedKey::EphemeralAuthorization { global: true },
                ..
            }
        )),
        "{events:?}"
    );
    assert!(!events.iter().any(|e| matches!(
        e,
        ApsEvent::TransportKey {
            key: TransportedKey::Network { .. },
            ..
        }
    )));
    let session = w.nodes[r].0.direct_legacy_session(1).unwrap();
    assert_eq!(
        session.phase,
        Phase::Ephemeral {
            authenticated: false
        }
    );
    assert!(w.nodes[r].0.stack.aps.security.entry(zvd_ieee).is_some());
    // No network key ever crossed the link.
    let leaked = w.nodes[r].2.iter().any(|e| match e {
        Event::DirectTunnel { tlv, .. } => {
            let m = NpduMessage::parse(&tlv[2..]).unwrap();
            let (_, n) = Header::decode_prefix(m.npdu).unwrap();
            panweave_direct::rotation::forwarding_decision(&m.npdu[n..])
                == panweave_direct::rotation::Forwarding::Decline
        }
        _ => false,
    });
    assert!(!leaked);
    assert!(
        !w.nodes[r]
            .2
            .iter()
            .any(|e| matches!(e, Event::DirectTunnelDeclined { .. }))
    );

    // 2. The ephemeral filter: an unsecured APS frame to the Trust
    //    Center, or anything to someone else, is dropped.
    let unsecured_zdp = [0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x01, 0x02];
    assert_eq!(
        write(
            &mut w,
            &wrap(ShortAddress::COORDINATOR, 2, &unsecured_zdp),
            true
        ),
        Err(TunnelError::Dropped)
    );
    assert_eq!(
        write(&mut w, &wrap(zdd_short, 3, &unsecured_zdp), true),
        Err(TunnelError::Dropped)
    );

    // 3. The ZVD updates its Trust Center link key: Request Key
    //    (APS-secured, passes) -> Transport Key under the key-load key
    //    (end-to-end authentication) -> Verify Key (unsecured, passes
    //    now) -> Confirm Key under the data key -> the ZDD sends the
    //    Basic key and the ZVD is a child.
    zvd.request_key(
        ShortAddress::COORDINATOR,
        RequestKeyType::TrustCenterLinkKey,
        None,
    )
    .unwrap();
    let events = pump(&mut w, &mut zvd);
    assert!(
        events.iter().any(|e| matches!(
            e,
            ApsEvent::TransportKey {
                key: TransportedKey::TrustCenterLink { .. },
                ..
            }
        )),
        "{events:?}"
    );
    assert_eq!(
        w.nodes[r].0.direct_legacy_session(1).unwrap().phase,
        Phase::Ephemeral {
            authenticated: true
        }
    );
    zvd.verify_key(
        tc_ieee,
        ShortAddress::COORDINATOR,
        KeyType::TrustCenterLinkKey,
    )
    .unwrap();
    let events = pump(&mut w, &mut zvd);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ApsEvent::ConfirmKey { .. })),
        "{events:?}"
    );
    let basic = events.iter().find_map(|e| match e {
        ApsEvent::TransportKey {
            key: TransportedKey::BasicAuthorization { key, source, .. },
            ..
        } => Some((key.clone(), *source)),
        _ => None,
    });
    assert_eq!(
        basic,
        Some((basic_key::<SoftwareAes>(zvd_ieee, &nwk_key), tc_ieee)),
        "{events:?}"
    );
    assert_eq!(
        w.nodes[r].0.direct_legacy_session(1).unwrap().phase,
        Phase::Basic
    );
    let child = w.nodes[r]
        .0
        .stack
        .nwk
        .neighbors
        .by_extended(zvd_ieee)
        .unwrap();
    assert!(child.relationship.is_authenticated_child());
    // The Basic key was the ZDD's doing: its own address is in the
    // auxiliary header of the frame that carried it.
    let carrier = w.nodes[r].2.iter().rev().find_map(|e| match e {
        Event::DirectTunnel { link: 1, tlv } => {
            let m = NpduMessage::parse(&tlv[2..]).unwrap();
            let (_, n) = Header::decode_prefix(m.npdu).ok()?;
            let aps = &m.npdu[n..];
            (aps[0] & 0x03 == 0x01 && aps.get(2).is_some_and(|c| (c >> 3) & 0x03 == 0x03))
                .then(|| panweave_direct::legacy::aux_source(aps))
                .flatten()
        }
        _ => None,
    });
    assert_eq!(carrier, Some(zdd_ieee));
    let _ = KeyDescriptor::EphemeralAuthorization { global: true };

    // 4. Later the ZVD comes back after a missed key rotation: a Trust
    //    Center rejoin over a Limited Authorization session; the legacy
    //    Trust Center tunnels the network key again, the ZDD answers
    //    with a Basic key derived from the active network key instead.
    w.nodes[r].0.close_tunnel(1);
    w.nodes[c]
        .0
        .stack
        .update_network_key(Key128::from_bytes([0x6b; 16]))
        .unwrap();
    w.run_until(Duration::from_secs(20), |_| false);
    assert!(w.nodes[r].0.open_tunnel(1, 0x0044, zvd_ieee));
    let cmd = NwkCommand::CommissioningRequest(CommissioningRequest {
        kind: CommissioningType::Rejoin,
        capability: MacCapability(0)
            .with_rx_on_when_idle(true)
            .with_allocate_address(true),
        tlvs: &tlvs,
    });
    let header = Header::new(FrameType::Command, zdd_short, zvd_short, 1, 9)
        .with_src_ieee(zvd_ieee)
        .with_dst_ieee(zdd_ieee);
    let h = header.encode_to_slice(&mut npdu).unwrap();
    let n = cmd.encode_to_slice(&mut npdu[h..]).unwrap();
    write(&mut w, &npdu[..h + n], false).unwrap();
    let events = pump(&mut w, &mut zvd);
    let basic = events.iter().find_map(|e| match e {
        ApsEvent::TransportKey {
            key: TransportedKey::BasicAuthorization { key, sequence, .. },
            ..
        } => Some((key.clone(), *sequence)),
        _ => None,
    });
    assert_eq!(
        basic,
        Some((
            basic_key::<SoftwareAes>(zvd_ieee, &Key128::from_bytes([0x6b; 16])),
            panweave::types::KeySequenceNumber(1)
        )),
        "{events:?}"
    );
    assert!(!events.iter().any(|e| matches!(
        e,
        ApsEvent::TransportKey {
            key: TransportedKey::Network { .. },
            ..
        }
    )));
    assert!(w.nodes[r].0.direct_legacy_session(1).is_none());
    let child = w.nodes[r]
        .0
        .stack
        .nwk
        .neighbors
        .by_extended(zvd_ieee)
        .unwrap();
    assert!(child.relationship.is_authenticated_child());

    // 5. A second ZVD that never authenticates is dropped after
    //    apsSecurityTimeOutPeriod, and the host told to disconnect.
    let other = ExtendedAddress(0x00AD_0000_0000_000A);
    let other_short = ShortAddress(0x4E22);
    assert!(w.nodes[r].0.open_tunnel(2, 0x0043, other));
    let tlvs = joiner_tlvs(other_short);
    let header = Header::new(FrameType::Command, zdd_short, other_short, 1, 1)
        .with_src_ieee(other)
        .with_dst_ieee(zdd_ieee);
    let cmd = NwkCommand::CommissioningRequest(CommissioningRequest {
        kind: CommissioningType::InitialJoin,
        capability: MacCapability(0)
            .with_rx_on_when_idle(true)
            .with_allocate_address(true),
        tlvs: &tlvs,
    });
    let h = header.encode_to_slice(&mut npdu).unwrap();
    let n = cmd.encode_to_slice(&mut npdu[h..]).unwrap();
    let mut tlv = [0u8; 200];
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
    assert!(w.run_until(Duration::from_secs(10), |w| {
        w.nodes[r].0.direct_legacy_session(2).is_some()
    }));
    assert!(
        w.nodes[r]
            .0
            .stack
            .nwk
            .neighbors
            .by_extended(other)
            .is_some()
    );
    assert!(w.run_until(Duration::from_secs(30), |w| {
        w.nodes[r]
            .2
            .iter()
            .any(|e| matches!(e, Event::DirectAuthorizationTimeout { link: 2 }))
    }));
    assert!(w.nodes[r].0.direct_legacy_session(2).is_none());
    assert!(
        w.nodes[r]
            .0
            .stack
            .nwk
            .neighbors
            .by_extended(other)
            .is_none()
    );
    // The first ZVD is unaffected.
    assert!(
        w.nodes[r]
            .0
            .stack
            .nwk
            .neighbors
            .by_extended(zvd_ieee)
            .is_some_and(|n| n.relationship.is_authenticated_child())
    );
}

/// The ZDD's security state (ZD 1.1 §6.2, §6.3.1, §6.6) at the facade:
/// an un-provisioned ZDD advertises for `NEW_ZDD_PROVISIONING_TIMEOUT`,
/// admits only provisioning sessions, then stops advertising until
/// woken again; a provisioned one admits authorized ZVDs, new ones only
/// while the network is open, and no provisioning session from a ZVD
/// holding an authorization session; leaving reopens provisioning.
#[test]
fn the_zdd_security_state_follows_the_network_and_the_sessions() {
    use panweave::direct::NEW_ZDD_PROVISIONING_TIMEOUT;
    use panweave_direct::state::{Interface, Refusal};
    use panweave_direct::tlv::Psk;

    let mut w = World {
        medium: VirtualMedium::new(),
        clock: VirtualClock::new(),
        nodes: Vec::new(),
    };
    let zvd = ExtendedAddress(0x00AA_0000_0000_0001);
    let mut coord = Coordinator::new(ExtendedAddress(0x00DD_0000_0000_0001))
        .build::<SoftwareAes, _, _>(TestRng::seed(1), MemoryStorage::new());
    coord.stack.config.trust_center_policy.allow_joins = true;
    coord.initialize().unwrap();
    let c = w.add(coord);
    w.settle();
    let advertising = |w: &World| -> Vec<bool> {
        w.nodes[c]
            .2
            .iter()
            .filter_map(|e| match e {
                Event::DirectAdvertising { enabled } => Some(*enabled),
                _ => None,
            })
            .collect()
    };
    assert_eq!(advertising(&w), vec![true]);
    assert!(matches!(
        w.nodes[c].0.direct.security.interface(),
        Interface::OpenToBeProvisioned { .. }
    ));
    assert_eq!(
        w.nodes[c].0.direct_admit(zvd, Psk::BasicAuthorization),
        Err(Refusal::NotProvisioned)
    );
    assert_eq!(
        w.nodes[c].0.direct_admit(zvd, Psk::Anonymous),
        Ok(Level::Provisioning)
    );
    // Nobody provisions it: the advertisement stops.
    w.run_until(
        NEW_ZDD_PROVISIONING_TIMEOUT + Duration::from_secs(1),
        |_| false,
    );
    assert_eq!(advertising(&w), vec![true, false]);
    assert_eq!(
        w.nodes[c].0.direct_admit(zvd, Psk::Anonymous),
        Err(Refusal::InterfaceOff)
    );
    // A user action wakes it; a provisioning session opens and the
    // ZVD forms the network through it.
    w.nodes[c].0.direct_power_up();
    w.settle();
    assert_eq!(advertising(&w), vec![true, false, true]);
    w.nodes[c].0.direct_session_opened(zvd, Level::Provisioning);
    w.run_until(
        NEW_ZDD_PROVISIONING_TIMEOUT + Duration::from_secs(1),
        |_| false,
    );
    assert_eq!(
        advertising(&w),
        vec![true, false, true],
        "held by the session"
    );
    w.nodes[c]
        .0
        .form_network_with_key(Key128::from_bytes([0x5a; 16]))
        .unwrap();
    assert!(w.run_until(Duration::from_secs(30), |w| {
        w.nodes[c].0.direct.security.is_provisioned()
    }));
    assert_eq!(
        w.nodes[c].0.direct.security.interface(),
        Interface::OpenToConnect
    );
    w.nodes[c].0.direct_session_closed(zvd);
    // Provisioned: authorized ZVDs at any time, new ones only while the
    // network is open (the anonymous secret while the countdown runs).
    assert_eq!(
        w.nodes[c].0.direct_admit(zvd, Psk::AdminAuthorization),
        Ok(Level::Admin)
    );
    assert_eq!(
        w.nodes[c].0.direct_admit(zvd, Psk::InstallCode),
        Err(Refusal::NetworkClosed)
    );
    w.nodes[c].0.stack.permit_join_network(60).unwrap();
    assert_eq!(
        w.nodes[c].0.direct_admit(zvd, Psk::InstallCode),
        Ok(Level::Provisioning)
    );
    assert_eq!(
        w.nodes[c].0.direct_admit(zvd, Psk::Anonymous),
        Ok(Level::Provisioning)
    );
    w.nodes[c].0.direct_session_opened(zvd, Level::Basic);
    assert_eq!(
        w.nodes[c].0.direct_admit(zvd, Psk::Anonymous),
        Err(Refusal::AuthorizationSessionActive)
    );
    assert_eq!(
        w.nodes[c]
            .0
            .direct_admit(ExtendedAddress(0x00AA_0000_0000_0002), Psk::Anonymous),
        Ok(Level::Provisioning)
    );
    // The countdown ran out: anonymous provisioning ends, others go on.
    w.run_until(Duration::from_secs(3601), |_| false);
    w.nodes[c].0.stack.permit_join_network(60).unwrap();
    assert_eq!(
        w.nodes[c]
            .0
            .direct_admit(ExtendedAddress(0x00AA_0000_0000_0002), Psk::Anonymous),
        Err(Refusal::AnonymousJoinExpired)
    );
    assert_eq!(
        w.nodes[c]
            .0
            .direct_admit(ExtendedAddress(0x00AA_0000_0000_0002), Psk::Passcode),
        Ok(Level::Provisioning)
    );
    // Leaving the network reopens provisioning.
    w.nodes[c].0.factory_reset().unwrap();
    w.run_until(Duration::from_secs(5), |_| false);
    assert!(!w.nodes[c].0.direct.security.is_provisioned());
    assert!(matches!(
        w.nodes[c].0.direct.security.interface(),
        Interface::OpenToBeProvisioned { .. }
    ));
}
