//! Dynamic Link Key negotiation while joining (R23.2 §4.6.3.5, §4.7.3.3):
//! the Trust Center asks the joiner to negotiate through its parent
//! (Security_Start_Key_Update_req → Security_Start_Key_Negotiation_req/rsp
//! relayed by the router), the SPEKE key is verified with Verify / Confirm
//! Key, and only then is the network key transported. Covers the
//! anonymous (well-known passphrase) and install-code authenticated
//! variants, the authentication token, and a failed negotiation.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_security::key_hierarchy::link_key_from_install_code;
use panweave_security::material::{
    InitialJoinAuthentication, KeyNegotiationState, LinkKeyEntry, LinkKeyKind, PostJoinKeyUpdate,
};
use panweave_security::trust_center::InstallCodePolicy;
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, DeviceId, Endpoint, ExtendedAddress, InstallCode, Key128, KeyAttributes,
    LogicalDeviceType, ProfileId,
};
use panweave_zcl::clusters::{identify, on_off};
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

const COORD: ExtendedAddress = ExtendedAddress(0x00EE_0000_0000_0001);
const ROUTER: ExtendedAddress = ExtendedAddress(0x00EE_0000_0000_0002);
const JOINER: ExtendedAddress = ExtendedAddress(0x00EE_0000_0000_0003);
const NETWORK_KEY: Key128 = Key128::from_bytes([0x77; 16]);

fn endpoint() -> (SimpleDescriptor, panweave_runtime::StackEndpoint) {
    let desc = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0100),
        1,
        &[ClusterId(0), identify::ID, on_off::ID],
        &[],
    )
    .unwrap();
    let mut ep = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    ep.add_instance(identify::server().unwrap()).unwrap();
    ep.add_instance(on_off::server().unwrap()).unwrap();
    (desc, ep)
}

fn stack(cfg: StackConfig, seed: u64) -> SimStack {
    let mut s = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
    let (d, e) = endpoint();
    s.add_endpoint(d, e).unwrap();
    s
}

fn joined(sim: &Simulator, i: usize) -> bool {
    sim.events(i)
        .iter()
        .any(|e| matches!(e, StackEvent::Joined { .. }))
}

/// Coordinator + router on a network; the router joins with anonymous
/// key negotiation (the Trust Center is its parent), then the policy for
/// later joiners is set to `policy`.
fn network(policy: InstallCodePolicy) -> (Simulator, usize, usize) {
    let mut sim = Simulator::new();
    let mut ccfg = StackConfig::new(LogicalDeviceType::Coordinator, COORD);
    ccfg.trust_center_policy.allow_joins = true;
    ccfg.trust_center_policy.install_codes = InstallCodePolicy::OptionalWithAnonymousNegotiation;
    let c = sim.add_stack("coord", stack(ccfg, 1), Box::new(OnOffApp::default()));
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(180).unwrap();
    let mut rcfg = StackConfig::new(LogicalDeviceType::Router, ROUTER);
    rcfg.trust_center_policy.allow_joins = true;
    let r = sim.add_stack("router", stack(rcfg, 2), Box::new(OnOffApp::default()));
    sim.stack(r).join(JoinMode::Association).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(60), |x| joined(x, r)),
        "router: {:?}
coord: {:?}",
        sim.events(r),
        sim.events(c)
    );
    // The router negotiated its key with the Trust Center as parent.
    let e = sim.stack(c).aps.security.entry(ROUTER).unwrap();
    assert_eq!(e.attributes, KeyAttributes::VerifiedKey);
    assert_eq!(e.negotiation_state, KeyNegotiationState::Complete);
    sim.run_for(Duration::from_secs(3));
    sim.stack(c).config.trust_center_policy.install_codes = policy;
    sim.stack(c).permit_join_network(180).unwrap();
    sim.run_for(Duration::from_secs(2));
    sim.take_events(c);
    (sim, c, r)
}

#[test]
fn anonymous_key_negotiation_join_through_router() {
    let (mut sim, c, r) = network(InstallCodePolicy::OptionalWithAnonymousNegotiation);
    let j = sim.add_stack(
        "joiner",
        stack(StackConfig::new(LogicalDeviceType::EndDevice, JOINER), 3),
        Box::new(OnOffApp::default()),
    );
    // Force the router to be the parent.
    sim.block(c, j);
    sim.stack(j).join(JoinMode::Association).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(60), |x| joined(x, j)),
        "joiner: {:?}\ncoord: {:?}",
        sim.events(j),
        sim.events(c)
    );
    let router_short = sim.stack(r).short_address();
    assert_eq!(sim.stack(j).nwk.nib.parent_address, router_short);
    // Both sides hold the same negotiated, verified, unique key.
    let tc_entry = sim.stack(c).aps.security.entry(JOINER).unwrap().clone();
    let j_entry = sim.stack(j).aps.security.entry(COORD).unwrap().clone();
    assert_eq!(tc_entry.key.as_bytes(), j_entry.key.as_bytes());
    assert_ne!(
        tc_entry.key.as_bytes(),
        Key128::WELL_KNOWN_GLOBAL_TCLK.as_bytes()
    );
    assert_eq!(tc_entry.attributes, KeyAttributes::VerifiedKey);
    assert_eq!(j_entry.attributes, KeyAttributes::VerifiedKey);
    assert_eq!(tc_entry.kind, LinkKeyKind::Unique);
    assert_eq!(tc_entry.negotiation_state, KeyNegotiationState::Complete);
    assert_eq!(
        tc_entry.initial_join_authentication,
        InitialJoinAuthentication::AnonymousKeyNegotiation
    );
    assert_eq!(
        tc_entry.post_join_key_update,
        PostJoinKeyUpdate::UnauthenticatedNegotiation
    );
    assert_eq!(
        j_entry.initial_join_authentication,
        InitialJoinAuthentication::AnonymousKeyNegotiation
    );
    // The negotiated key is unique: no Request Key exchange follows.
    assert!(
        sim.events(j)
            .iter()
            .any(|e| matches!(e, StackEvent::LinkKeyUpdated))
    );
    sim.run_for(Duration::from_secs(5));
    assert!(sim.stack(j).is_operating());
    assert!(
        !sim.events(j)
            .iter()
            .any(|e| matches!(e, StackEvent::KeyNegotiationFailed { .. }))
    );
    // §2.4.3.4.2: the joiner obtained its authentication token once; both
    // sides hold the same passphrase and the Trust Center locked it.
    assert!(
        sim.events(j)
            .iter()
            .any(|e| matches!(e, StackEvent::AuthenticationTokenStored)),
        "{:?}",
        sim.events(j)
    );
    let tc_entry = sim.stack(c).aps.security.entry(JOINER).unwrap().clone();
    let j_entry = sim.stack(j).aps.security.entry(COORD).unwrap().clone();
    assert!(tc_entry.frame_counter_sync);
    assert!(!tc_entry.passphrase_update_allowed);
    assert!(!j_entry.passphrase_update_allowed);
    assert_eq!(
        tc_entry.passphrase.as_ref().map(Key128::as_bytes),
        j_entry.passphrase.as_ref().map(Key128::as_bytes)
    );
    assert_ne!(
        j_entry.passphrase.as_ref().unwrap().as_bytes(),
        b"ZigBeeAlliance18"
    );
}

#[test]
fn install_code_authenticated_negotiation() {
    let (mut sim, c, _r) = network(InstallCodePolicy::Required);
    let code = InstallCode::new(&[
        0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x97, 0x23, 0xA5, 0xC6, 0x39, 0xB2, 0x69, 0x16, 0xD5,
        0x05, 0xC3, 0xB5,
    ])
    .unwrap();
    let ic_key = link_key_from_install_code::<panweave_security::cipher::SoftwareAes>(&code);
    // The commissioner entered the install code at the Trust Center
    // (§4.7.3.3): unique provisional entry with the derived key.
    let mut entry = LinkKeyEntry::provisional(JOINER, ic_key.clone(), LinkKeyKind::Unique);
    entry.initial_join_authentication = InitialJoinAuthentication::InstallCodeKey;
    sim.stack(c).aps.install_link_key(entry).unwrap();
    sim.stack(c).flush();
    let mut jcfg = StackConfig::new(LogicalDeviceType::EndDevice, JOINER);
    jcfg.preconfigured_link_key = (COORD, ic_key.clone(), LinkKeyKind::Unique);
    let j = sim.add_stack("joiner", stack(jcfg, 4), Box::new(OnOffApp::default()));
    sim.stack(j).join(JoinMode::Association).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(60), |x| joined(x, j)),
        "joiner: {:?}\ncoord: {:?}",
        sim.events(j),
        sim.events(c)
    );
    let tc_entry = sim.stack(c).aps.security.entry(JOINER).unwrap().clone();
    let j_entry = sim.stack(j).aps.security.entry(COORD).unwrap().clone();
    assert_eq!(tc_entry.key.as_bytes(), j_entry.key.as_bytes());
    assert_ne!(tc_entry.key.as_bytes(), ic_key.as_bytes());
    assert_eq!(tc_entry.attributes, KeyAttributes::VerifiedKey);
    assert_eq!(
        tc_entry.post_join_key_update,
        PostJoinKeyUpdate::AuthenticatedNegotiation
    );
    assert_eq!(
        j_entry.initial_join_authentication,
        InitialJoinAuthentication::KeyNegotiationWithAuthentication
    );
}

#[test]
fn wrong_passphrase_fails_and_restores_the_entry() {
    let (mut sim, c, _r) = network(InstallCodePolicy::Required);
    let good = Key128::from_bytes([0x11; 16]);
    let bad = Key128::from_bytes([0x22; 16]);
    let entry = LinkKeyEntry::provisional(JOINER, good, LinkKeyKind::Unique);
    sim.stack(c).aps.install_link_key(entry).unwrap();
    sim.stack(c).flush();
    let mut jcfg = StackConfig::new(LogicalDeviceType::EndDevice, JOINER);
    jcfg.preconfigured_link_key = (COORD, bad.clone(), LinkKeyKind::Unique);
    let j = sim.add_stack("joiner", stack(jcfg, 5), Box::new(OnOffApp::default()));
    sim.stack(j).join(JoinMode::Association).unwrap();
    // Verify Key fails at the Trust Center (different SPEKE keys): the
    // joiner never receives the network key and times out.
    assert!(sim.run_until(Duration::from_secs(90), |x| {
        x.events(j)
            .iter()
            .any(|e| matches!(e, StackEvent::JoinFailed(_)))
    }));
    assert!(!joined(&sim, j));
    // The joiner restored its pre-configured entry.
    let e = sim.stack(j).aps.security.entry(COORD).unwrap();
    assert_eq!(e.key.as_bytes(), bad.as_bytes());
    assert_eq!(e.attributes, KeyAttributes::ProvisionalKey);
    // The Trust Center did not hand out the network key.
    assert!(!sim.events(c).iter().any(|e| matches!(
        e,
        StackEvent::DeviceAuthorized { ieee, .. } if *ieee == JOINER
    )));
}

#[test]
fn rebooted_trust_center_synchronizes_frame_counters() {
    use panweave_codec::Writer;
    use panweave_zdo::security::{GetAuthenticationLevelReq, TargetIeee};
    let (mut sim, c, r) = network(InstallCodePolicy::OptionalWithAnonymousNegotiation);
    // The router negotiated its key: the Trust Center marked it as
    // supporting frame counter synchronization.
    assert!(
        sim.stack(c)
            .aps
            .security
            .entry(ROUTER)
            .unwrap()
            .frame_counter_sync
    );
    assert!(
        sim.stack(r)
            .aps
            .security
            .entry(COORD)
            .unwrap()
            .frame_counter_sync
    );

    // Reboot the Trust Center from its storage: incoming counters are
    // unverified (§4.6.3.8).
    let storage = sim.stack(c).storage.clone();
    sim.isolate(c);
    let mut ccfg = StackConfig::new(LogicalDeviceType::Coordinator, COORD);
    ccfg.trust_center_policy.allow_joins = true;
    let mut fresh = stack(ccfg, 9);
    fresh.storage = storage;
    assert_eq!(
        fresh.restore().unwrap(),
        panweave_runtime::Restored::OnNetwork
    );
    assert!(
        !fresh
            .aps
            .security
            .entry(ROUTER)
            .unwrap()
            .verified_frame_counter
    );
    fresh.poll(sim.clock.now());
    fresh.resume().unwrap();
    let c2 = sim.add_stack("coord2", fresh, Box::new(OnOffApp::default()));
    sim.run_for(Duration::from_secs(3));
    sim.take_events(r);

    // The router sends an APS-encrypted request: dropped, challenged,
    // synchronized; the request itself times out.
    let mut buf = [0u8; 16];
    let mut w = Writer::new(&mut buf);
    TargetIeee(JOINER).write(&mut w).unwrap();
    let n = w.position();
    let req = GetAuthenticationLevelReq { tlvs: &buf[..n] };
    sim.stack(r)
        .zdo
        .request_secured(
            panweave_types::ShortAddress::COORDINATOR,
            panweave_zdo::cluster::SECURITY_GET_AUTHENTICATION_LEVEL_REQ,
            &req,
        )
        .unwrap();
    sim.stack(r).flush();
    assert!(sim.run_until(Duration::from_secs(20), |x| {
        x.events(c2)
            .iter()
            .any(|e| matches!(e, StackEvent::FrameCounterSynchronized { partner } if *partner == ROUTER))
    }), "{:?}", sim.events(c2));
    assert!(
        sim.stack(c2)
            .aps
            .security
            .entry(ROUTER)
            .unwrap()
            .verified_frame_counter
    );
    assert!(
        sim.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::ZdpTimeout { .. }))
    );
    sim.take_events(r);
    // A retry is answered (NO_MATCH: JOINER never joined this network).
    sim.stack(r)
        .zdo
        .request_secured(
            panweave_types::ShortAddress::COORDINATOR,
            panweave_zdo::cluster::SECURITY_GET_AUTHENTICATION_LEVEL_REQ,
            &req,
        )
        .unwrap();
    sim.stack(r).flush();
    assert!(
        sim.run_until(Duration::from_secs(10), |x| {
            x.events(r).iter().any(|e| matches!(
            e,
            StackEvent::Zdp(z) if z.cluster == ClusterId(0x8042) && z.data.first() == Some(&0x86)
        ))
        }),
        "{:?}",
        sim.events(r)
    );
}

/// Device interview (BDB 3.1 §9.9): with `interview_joiners` the Trust
/// Center reports the verified joiner and holds the network key until
/// the application admits it; a rejected joiner is removed.
#[test]
fn interview_holds_the_network_key_until_admitted() {
    let (mut sim, c, r) = network(InstallCodePolicy::OptionalWithAnonymousNegotiation);
    sim.stack(c).config.trust_center_policy.interview_joiners = true;
    let j = sim.add_stack(
        "joiner",
        stack(StackConfig::new(LogicalDeviceType::EndDevice, JOINER), 3),
        Box::new(OnOffApp::default()),
    );
    sim.block(c, j);
    sim.stack(j).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::JoinerVerified { device, .. } if *device == JOINER))
    }));
    // Nothing more happens without the application: no network key.
    sim.run_for(Duration::from_secs(3));
    assert!(!joined(&sim, j));
    assert_eq!(
        sim.stack(c).aps.security.entry(JOINER).unwrap().attributes,
        KeyAttributes::VerifiedKey
    );
    // Admitted: the key goes through the router and the joiner is on.
    sim.stack(c).admit_joiner(JOINER).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| joined(x, j)));
    assert!(sim.stack(c).admit_joiner(JOINER).is_err());
    let _ = r;
}

#[test]
fn interview_rejection_removes_the_joiner() {
    let (mut sim, c, _r) = network(InstallCodePolicy::OptionalWithAnonymousNegotiation);
    sim.stack(c).config.trust_center_policy.interview_joiners = true;
    let j = sim.add_stack(
        "joiner",
        stack(StackConfig::new(LogicalDeviceType::EndDevice, JOINER), 3),
        Box::new(OnOffApp::default()),
    );
    sim.block(c, j);
    sim.stack(j).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::JoinerVerified { device, .. } if *device == JOINER))
    }));
    sim.stack(c).reject_joiner(JOINER).unwrap();
    assert!(sim.stack(c).aps.security.entry(JOINER).is_none());
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(j)
            .iter()
            .any(|e| matches!(e, StackEvent::JoinFailed(_) | StackEvent::Left { .. }))
    }));
    assert!(!joined(&sim, j));
}
