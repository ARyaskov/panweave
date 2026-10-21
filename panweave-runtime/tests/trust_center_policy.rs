//! Trust Center authorization policy (`panweave_runtime::authorization`):
//! `bdbTrustCenterRequireKeyExchange` has real effects. A device that
//! received the network key is pending until it holds a verified unique
//! link key; pending devices get no application access, are removed when
//! their window passes, and restarts never promote them. These tests
//! assert the Trust Center's security state, not only frame delivery.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_mac::service::MacServiceConfig;
use panweave_runtime::join_trace::{JoinStage, decision};
use panweave_runtime::{Authorization, JoinMode, Restored, StackConfig, StackEvent};
use panweave_security::material::LinkKeyKind;
use panweave_security::trust_center::TrustCenterPolicy;
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::CommandId;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, Endpoint, ExtendedAddress, Key128, KeyAttributes, LogicalDeviceType, ProfileId,
    ShortAddress,
};
use panweave_zcl::Direction;
use panweave_zcl::frame::Header;

const NETWORK_KEY: Key128 = Key128::from_bytes([0x4D; 16]);
const TC: ExtendedAddress = ExtendedAddress(0x00C0_0000_0000_0001);
const DEV: ExtendedAddress = ExtendedAddress(0x00C0_0000_0000_0002);
const OTHER: ExtendedAddress = ExtendedAddress(0x00C0_0000_0000_0003);
/// A synthetic, non-production install-code-derived key.
const PRESHARED: Key128 = Key128::from_bytes([0xA5; 16]);

fn sim_stack(cfg: StackConfig, seed: u64) -> SimStack {
    SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    )
}

/// A Trust Center that does not offer dynamic link key negotiation: a
/// joiner with a pre-shared key then gets the network key under that key
/// and must still run the link-key exchange. (Negotiation is the other
/// valid path, tested separately.)
fn tc_config() -> StackConfig {
    let mut cfg = StackConfig::new(LogicalDeviceType::Coordinator, TC);
    cfg.trust_center_policy.allow_joins = true;
    cfg.trust_center_policy.dlk_enabled = false;
    cfg
}

/// A Trust Center with an open network.
fn network(cfg: StackConfig) -> (Simulator, usize) {
    let mut sim = Simulator::new();
    sim.trace_enabled = true;
    let c = sim.add_stack("tc", sim_stack(cfg, 1), Box::new(OnOffApp::default()));
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(240).unwrap();
    (sim, c)
}

/// A standard Zigbee 3.0 joiner (well-known key, requests a unique Trust
/// Center link key after joining).
fn joiner(sim: &mut Simulator, ieee: ExtendedAddress, seed: u64) -> usize {
    let cfg = StackConfig::new(LogicalDeviceType::Router, ieee);
    let d = sim.add_stack("dev", sim_stack(cfg, seed), Box::new(OnOffApp::default()));
    sim.stack(d).join(JoinMode::Association).unwrap();
    d
}

/// A joiner holding a unique pre-shared (install-code style) key that
/// never runs the link-key exchange: the Trust Center knows the key, so
/// the network key reaches it, but it never proves a new key.
fn non_exchanging_joiner(sim: &mut Simulator, c: usize, ieee: ExtendedAddress, seed: u64) -> usize {
    sim.stack(c)
        .install_link_key(ieee, PRESHARED, LinkKeyKind::Unique, true);
    let mut cfg = StackConfig::new(LogicalDeviceType::Router, ieee);
    cfg.preconfigured_link_key = (TC, PRESHARED, LinkKeyKind::Unique);
    let d = sim.add_stack(
        "legacy",
        sim_stack(cfg, seed),
        Box::new(OnOffApp::default()),
    );
    sim.stack(d).join(JoinMode::Association).unwrap();
    d
}

fn count(sim: &Simulator, c: usize, pred: impl Fn(&StackEvent) -> bool) -> usize {
    sim.events(c).iter().filter(|e| pred(e)).count()
}

fn authorized_events(sim: &Simulator, c: usize, ieee: ExtendedAddress) -> usize {
    count(
        sim,
        c,
        |e| matches!(e, StackEvent::DeviceAuthorized { ieee: i, .. } if *i == ieee),
    )
}

fn pending_event(sim: &Simulator, c: usize, ieee: ExtendedAddress) -> bool {
    count(
        sim,
        c,
        |e| matches!(e, StackEvent::KeyExchangePending { ieee: i, .. } if *i == ieee),
    ) > 0
}

fn timed_out(sim: &Simulator, c: usize, ieee: ExtendedAddress) -> bool {
    count(
        sim,
        c,
        |e| matches!(e, StackEvent::KeyExchangeTimedOut { ieee: i } if *i == ieee),
    ) > 0
}

fn stages(sim: &mut Simulator, c: usize, ieee: ExtendedAddress) -> Vec<(JoinStage, u8)> {
    let mut out = Vec::new();
    while let Some(r) = sim.stack(c).next_join_record() {
        if r.device == ieee {
            out.push((r.stage, r.detail));
        }
    }
    out
}

/// Sends a ZCL On/Off Toggle from `d` to the Trust Center.
fn application_frame(sim: &mut Simulator, d: usize) {
    let seq = sim.stack(d).zcl.next_seq();
    let header = Header::cluster_specific(seq, CommandId(2), Direction::ToServer);
    sim.stack(d)
        .zcl_send(
            panweave_aps::Destination::Short {
                address: ShortAddress::COORDINATOR,
                endpoint: Endpoint(1),
            },
            ProfileId::HOME_AUTOMATION,
            ClusterId(0x0006),
            Endpoint(1),
            &header,
            &[],
        )
        .unwrap();
    sim.run_for(Duration::from_secs(2));
}

fn authorized_join(sim: &mut Simulator, c: usize, ieee: ExtendedAddress, seed: u64) -> usize {
    let d = joiner(sim, ieee, seed);
    assert!(
        sim.run_until(Duration::from_secs(60), |x| authorized_events(x, c, ieee)
            > 0),
        "tc: {:?}",
        sim.events(c)
    );
    d
}

#[test]
fn the_default_policy_requires_the_key_exchange() {
    let p = TrustCenterPolicy::default();
    assert!(p.require_key_exchange);
    assert_eq!(
        p.node_join_timeout_s, 15,
        "BDB 3.1 bdbTrustCenterNodeJoinTimeout"
    );
    let cfg = StackConfig::new(LogicalDeviceType::Coordinator, TC);
    assert!(cfg.trust_center_policy.require_key_exchange);
}

#[test]
fn a_standard_join_is_pending_until_the_key_exchange_completes() {
    let (mut sim, c) = network(tc_config());
    let d = authorized_join(&mut sim, c, DEV, 2);
    assert!(pending_event(&sim, c, DEV), "pending before authorized");
    let pending_at = sim
        .events(c)
        .iter()
        .position(|e| matches!(e, StackEvent::KeyExchangePending { ieee, .. } if *ieee == DEV))
        .unwrap();
    let authorized_at = sim
        .events(c)
        .iter()
        .position(|e| matches!(e, StackEvent::DeviceAuthorized { ieee, .. } if *ieee == DEV))
        .unwrap();
    assert!(pending_at < authorized_at);
    assert_eq!(authorized_events(&sim, c, DEV), 1);
    assert_eq!(
        sim.stack(c).device_authorization(DEV),
        Authorization::Authorized
    );
    let entry = sim.stack(c).aps.security.entry(DEV).unwrap();
    assert_eq!(entry.kind, LinkKeyKind::Unique);
    assert_eq!(entry.attributes, KeyAttributes::VerifiedKey);
    assert_ne!(
        entry.key.as_bytes(),
        Key128::WELL_KNOWN_GLOBAL_TCLK.as_bytes()
    );
    let got = stages(&mut sim, c, DEV);
    assert!(got.contains(&(JoinStage::Authorized, 0)), "{got:?}");
    // Application frames from an authorized device pass.
    let before = sim.stack(c).unauthorized_frames_dropped();
    application_frame(&mut sim, d);
    assert_eq!(sim.stack(c).unauthorized_frames_dropped(), before);
}

#[test]
fn a_device_that_never_exchanges_its_key_is_denied_and_removed() {
    let (mut sim, c) = network(tc_config());
    let d = non_exchanging_joiner(&mut sim, c, DEV, 2);
    assert!(sim.run_until(Duration::from_secs(30), |x| pending_event(x, c, DEV)));
    assert_eq!(
        sim.stack(c).device_authorization(DEV),
        Authorization::PendingKeyExchange
    );
    assert_eq!(authorized_events(&sim, c, DEV), 0);
    // Pending: its application frames are dropped.
    let before = sim.stack(c).unauthorized_frames_dropped();
    application_frame(&mut sim, d);
    assert!(sim.stack(c).unauthorized_frames_dropped() > before);
    // The window passes: link key gone, device asked to leave.
    assert!(sim.run_until(Duration::from_secs(30), |x| timed_out(x, c, DEV)));
    assert!(sim.stack(c).aps.security.entry(DEV).is_none());
    assert_eq!(
        sim.stack(c).device_authorization(DEV),
        Authorization::Unknown
    );
    assert_eq!(sim.stack(c).key_exchange_timeouts(), 1);
    assert_eq!(authorized_events(&sim, c, DEV), 0);
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(d)
            .iter()
            .any(|e| matches!(e, StackEvent::Left { .. }))
    }));
    let got = stages(&mut sim, c, DEV);
    assert!(
        got.iter()
            .any(|(s, _)| *s == JoinStage::KeyExchangeTimedOut),
        "{got:?}"
    );
    assert!(!got.iter().any(|(s, _)| *s == JoinStage::Authorized));
}

#[test]
fn a_started_but_unfinished_exchange_times_out() {
    // The device asks for its link key but never gets one it can verify
    // (here the policy refuses requests: the same state as a lost
    // exchange from the Trust Center's point of view).
    let mut cfg = tc_config();
    cfg.trust_center_policy.tclk_requests =
        panweave_security::trust_center::TclkRequestPolicy::Never;
    let (mut sim, c) = network(cfg);
    let _d = joiner(&mut sim, DEV, 2);
    assert!(sim.run_until(Duration::from_secs(30), |x| pending_event(x, c, DEV)));
    assert!(sim.run_until(Duration::from_secs(30), |x| timed_out(x, c, DEV)));
    let got = stages(&mut sim, c, DEV);
    assert!(got.contains(&(JoinStage::TclkRequested, 0)), "{got:?}");
    assert!(!got.iter().any(|(s, _)| *s == JoinStage::TclkVerified));
    assert_eq!(authorized_events(&sim, c, DEV), 0);
    assert!(sim.stack(c).aps.security.entry(DEV).is_none());
}

#[test]
fn a_negotiated_key_authorizes_without_a_window() {
    // Dynamic link key negotiation with the pre-shared key: the key is
    // verified before the network key goes out.
    let mut cfg = tc_config();
    cfg.trust_center_policy.dlk_enabled = true;
    let (mut sim, c) = network(cfg);
    non_exchanging_joiner(&mut sim, c, DEV, 2);
    assert!(
        sim.run_until(Duration::from_secs(60), |x| authorized_events(x, c, DEV)
            > 0)
    );
    assert!(!pending_event(&sim, c, DEV));
    assert_eq!(
        sim.stack(c).device_authorization(DEV),
        Authorization::Authorized
    );
}

#[test]
fn an_invalid_key_confirmation_does_not_authorize() {
    let (mut sim, c) = network(tc_config());
    let d = non_exchanging_joiner(&mut sim, c, DEV, 2);
    assert!(sim.run_until(Duration::from_secs(30), |x| pending_event(x, c, DEV)));
    // The Trust Center's entry holds a key the device does not have (as
    // after a transport the device never received): the device's Verify
    // Key carries the hash of the wrong key.
    let wrong = Key128::from_bytes([0x3C; 16]);
    assert!(sim.stack(c).aps.security.replace_key(
        DEV,
        wrong,
        KeyAttributes::UnverifiedKey,
        LinkKeyKind::Unique
    ));
    sim.stack(d)
        .aps
        .verify_key(
            TC,
            ShortAddress::COORDINATOR,
            panweave_types::KeyType::TrustCenterLinkKey,
        )
        .unwrap();
    sim.stack(d).flush();
    sim.run_for(Duration::from_secs(3));
    assert_eq!(
        sim.stack(c).aps.security.entry(DEV).unwrap().attributes,
        KeyAttributes::UnverifiedKey
    );
    assert_eq!(
        sim.stack(c).device_authorization(DEV),
        Authorization::PendingKeyExchange
    );
    assert_eq!(authorized_events(&sim, c, DEV), 0);
    assert!(sim.run_until(Duration::from_secs(30), |x| timed_out(x, c, DEV)));
}

#[test]
fn duplicate_and_replayed_messages_change_nothing() {
    let (mut sim, c) = network(tc_config());
    let d = authorized_join(&mut sim, c, DEV, 2);
    sim.run_for(Duration::from_secs(5));
    let key = sim.stack(c).aps.security.entry(DEV).unwrap().key.clone();
    // A duplicate Verify Key with the right key: still authorized once.
    sim.stack(d)
        .aps
        .verify_key(
            TC,
            ShortAddress::COORDINATOR,
            panweave_types::KeyType::TrustCenterLinkKey,
        )
        .unwrap();
    sim.stack(d).flush();
    sim.run_for(Duration::from_secs(3));
    assert_eq!(authorized_events(&sim, c, DEV), 1);
    assert_eq!(
        sim.stack(c).device_authorization(DEV),
        Authorization::Authorized
    );
    // Replay every frame the device sent (its Request Key and Verify Key
    // among them): NWK frame counters reject them, no new key is issued.
    let sent: Vec<Vec<u8>> = sim
        .trace
        .iter()
        .filter(|t| t.node == d)
        .map(|t| t.frame.clone())
        .collect();
    assert!(!sent.is_empty());
    let replays_before = sim.stack(c).nwk.stats.replays;
    let _ = stages(&mut sim, c, DEV);
    for f in &sent {
        sim.inject(f);
    }
    sim.run_for(Duration::from_secs(5));
    assert!(sim.stack(c).nwk.stats.replays > replays_before);
    assert_eq!(
        sim.stack(c).aps.security.entry(DEV).unwrap().key.as_bytes(),
        key.as_bytes(),
        "no new link key from a replayed Request Key"
    );
    let got = stages(&mut sim, c, DEV);
    assert!(
        !got.iter().any(|(s, _)| *s == JoinStage::TclkRequested),
        "a replayed Request Key never reaches the policy: {got:?}"
    );
    // The replayed (unsecured) association makes the Trust Center send
    // the network key again, under the device's own verified key: only
    // the genuine device can use it, and it stays authorized.
    assert_eq!(
        sim.stack(c).device_authorization(DEV),
        Authorization::Authorized
    );
}

#[test]
fn leaving_during_the_exchange_closes_the_window() {
    let (mut sim, c) = network(tc_config());
    let d = non_exchanging_joiner(&mut sim, c, DEV, 2);
    assert!(sim.run_until(Duration::from_secs(30), |x| pending_event(x, c, DEV)));
    sim.stack(d).leave(false).unwrap();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::DeviceLeft { ieee, .. } if *ieee == DEV))
    }));
    assert_eq!(sim.stack(c).pending_key_exchanges(), 0);
    assert_eq!(
        sim.stack(c).device_authorization(DEV),
        Authorization::KeyExchangeIncomplete
    );
    sim.run_for(Duration::from_secs(30));
    assert!(!timed_out(&sim, c, DEV), "nothing left to time out");
    assert_eq!(authorized_events(&sim, c, DEV), 0);
}

#[test]
fn a_secured_rejoin_with_valid_credentials_stays_authorized() {
    let (mut sim, c) = network(tc_config());
    let d = authorized_join(&mut sim, c, DEV, 2);
    sim.run_for(Duration::from_secs(5));
    sim.take_events(c);
    sim.stack(d).join(JoinMode::SecuredRejoin).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(60), |x| authorized_events(x, c, DEV)
            > 0),
        "tc: {:?}",
        sim.events(c)
    );
    assert!(
        !pending_event(&sim, c, DEV),
        "no new window for a verified key"
    );
    assert_eq!(
        sim.stack(c).device_authorization(DEV),
        Authorization::Authorized
    );
}

#[test]
fn a_trust_center_rejoin_without_valid_credentials_is_refused() {
    let (mut sim, c) = network(tc_config());
    let d = non_exchanging_joiner(&mut sim, c, DEV, 2);
    assert!(sim.run_until(Duration::from_secs(60), |x| timed_out(x, c, DEV)));
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(d)
            .iter()
            .any(|e| matches!(e, StackEvent::Left { .. }))
    }));
    let _ = stages(&mut sim, c, DEV);
    // Its key was removed: a Trust Center rejoin is ignored.
    let _ = sim.stack(d).join(JoinMode::TrustCenterRejoin);
    sim.run_for(Duration::from_secs(20));
    let got = stages(&mut sim, c, DEV);
    assert!(
        !got.iter().any(|(s, _)| *s == JoinStage::KeyTransportSent),
        "{got:?}"
    );
    if let Some((_, d)) = got.iter().find(|(s, _)| *s == JoinStage::Decision) {
        assert_eq!(*d, decision::IGNORE);
    }
    assert_eq!(authorized_events(&sim, c, DEV), 0);
    assert!(
        !sim.stack(c)
            .device_authorization(DEV)
            .grants_application_access()
    );
}

/// A Trust Center restarted from `sim`'s node `c` storage.
fn restarted(sim: &mut Simulator, c: usize) -> SimStack {
    sim.stack(c).flush();
    let storage = sim.stack(c).storage.clone();
    let mut tc = SimStack::new(
        tc_config(),
        MacServiceConfig::default(),
        TestRng::seed(9),
        storage,
    );
    assert_eq!(tc.restore().unwrap(), Restored::OnNetwork);
    tc
}

#[test]
fn authorization_survives_a_restart_but_pending_never_becomes_authorized() {
    let (mut sim, c) = network(tc_config());
    authorized_join(&mut sim, c, DEV, 2);
    non_exchanging_joiner(&mut sim, c, OTHER, 3);
    assert!(sim.run_until(Duration::from_secs(30), |x| pending_event(x, c, OTHER)));
    sim.run_for(Duration::from_secs(2));
    let tc = restarted(&mut sim, c);
    assert_eq!(tc.device_authorization(DEV), Authorization::Authorized);
    assert_eq!(
        tc.device_authorization(OTHER),
        Authorization::KeyExchangeIncomplete,
        "the pending state is not persisted evidence of authorization"
    );
    assert!(!tc.device_authorization(OTHER).grants_application_access());
    assert_eq!(tc.pending_key_exchanges(), 0);
}

#[test]
fn an_exemption_admits_only_its_device() {
    let (mut sim, c) = network(tc_config());
    sim.stack(c)
        .grant_commissioning_exemption(DEV, Duration::from_secs(60))
        .unwrap();
    let d = non_exchanging_joiner(&mut sim, c, DEV, 2);
    let o = non_exchanging_joiner(&mut sim, c, OTHER, 3);
    assert!(
        sim.run_until(Duration::from_secs(60), |x| authorized_events(x, c, DEV)
            > 0)
    );
    assert_eq!(
        sim.stack(c).device_authorization(DEV),
        Authorization::Exempt
    );
    assert!(sim.run_until(Duration::from_secs(60), |x| timed_out(x, c, OTHER)));
    assert_eq!(authorized_events(&sim, c, OTHER), 0);
    // The exemption waives the key exchange only: the exempt device's
    // frames pass, the other's never did.
    let before = sim.stack(c).unauthorized_frames_dropped();
    application_frame(&mut sim, d);
    assert_eq!(sim.stack(c).unauthorized_frames_dropped(), before);
    let _ = o;
    // Withdrawn: the device loses application access.
    sim.stack(c).set_key_exchange_exemption(DEV, false).unwrap();
    assert_eq!(
        sim.stack(c).device_authorization(DEV),
        Authorization::KeyExchangeIncomplete
    );
    application_frame(&mut sim, d);
    assert!(sim.stack(c).unauthorized_frames_dropped() > before);
    // Bounded.
    for i in 0..8u64 {
        let _ = sim
            .stack(c)
            .set_key_exchange_exemption(ExtendedAddress(0x1000 + i), true);
    }
    assert!(
        sim.stack(c)
            .set_key_exchange_exemption(ExtendedAddress(0x2000), true)
            .is_err()
    );
}

#[test]
fn a_policy_without_the_requirement_authorizes_on_key_delivery() {
    let mut cfg = tc_config();
    cfg.trust_center_policy.require_key_exchange = false;
    let (mut sim, c) = network(cfg);
    non_exchanging_joiner(&mut sim, c, DEV, 2);
    assert!(
        sim.run_until(Duration::from_secs(60), |x| authorized_events(x, c, DEV)
            > 0)
    );
    assert!(!pending_event(&sim, c, DEV));
    assert_eq!(
        sim.stack(c).device_authorization(DEV),
        Authorization::Authorized
    );
}

#[test]
fn network_key_updates_still_reach_authorized_devices() {
    let (mut sim, c) = network(tc_config());
    let d = authorized_join(&mut sim, c, DEV, 2);
    sim.run_for(Duration::from_secs(5));
    let seq = sim
        .stack(c)
        .update_network_key(Key128::from_bytes([0x6E; 16]))
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(120), |x| {
        x.stack_ref(d).nwk.security.active_sequence() == Some(seq)
    }));
    assert_eq!(
        sim.stack(c).device_authorization(DEV),
        Authorization::Authorized
    );
}

#[test]
fn an_exemption_does_not_authenticate_a_claimed_identity() {
    // The legacy path has no device secret: whoever joins first with the
    // exempted IEEE address within the window is admitted. This test
    // documents that limitation and what bounds it: one admission per
    // grant, and a later unauthenticated join under the same address
    // withdraws the admission instead of inheriting it.
    let (mut sim, c) = network(tc_config());
    sim.stack(c)
        .grant_commissioning_exemption(DEV, Duration::from_secs(120))
        .unwrap();
    let impostor = non_exchanging_joiner(&mut sim, c, DEV, 7);
    assert!(
        sim.run_until(Duration::from_secs(60), |x| authorized_events(x, c, DEV)
            > 0)
    );
    assert_eq!(
        sim.stack(c).device_authorization(DEV),
        Authorization::Exempt,
        "LIMITATION: the claimed address alone was enough"
    );
    assert!(
        sim.stack(c).commissioning_exemption(DEV).is_none(),
        "single use"
    );
    // The genuine device (same claimed address) joins afterwards.
    sim.stack(impostor).leave(false).unwrap();
    sim.run_for(Duration::from_secs(5));
    sim.isolate(impostor);
    sim.stack(c).permit_join_network(240).unwrap();
    sim.take_events(c);
    let _ = stages(&mut sim, c, DEV);
    let _genuine = non_exchanging_joiner(&mut sim, c, DEV, 8);
    assert!(sim.run_until(Duration::from_secs(60), |x| pending_event(x, c, DEV)));
    assert!(!sim.stack(c).key_exchange_exempt(DEV), "not inherited");
    let got = stages(&mut sim, c, DEV);
    assert!(
        got.iter().any(|(s, _)| *s == JoinStage::ExemptionWithdrawn),
        "{got:?}"
    );
    assert!(sim.run_until(Duration::from_secs(30), |x| timed_out(x, c, DEV)));
}

#[test]
fn an_exempt_device_rejoins_securely_but_not_through_the_trust_center() {
    let (mut sim, c) = network(tc_config());
    sim.stack(c)
        .grant_commissioning_exemption(DEV, Duration::from_secs(60))
        .unwrap();
    let d = non_exchanging_joiner(&mut sim, c, DEV, 2);
    assert!(
        sim.run_until(Duration::from_secs(60), |x| authorized_events(x, c, DEV)
            > 0)
    );
    sim.run_for(Duration::from_secs(3));
    sim.take_events(c);
    // A secured rejoin (it holds the network key): still admitted.
    sim.stack(d).join(JoinMode::SecuredRejoin).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(60), |x| authorized_events(x, c, DEV)
            > 0)
    );
    assert!(!pending_event(&sim, c, DEV));
    assert_eq!(
        sim.stack(c).device_authorization(DEV),
        Authorization::Exempt
    );
    // A Trust Center rejoin with its unverified pre-shared key is refused
    // by the policy (`allowRejoinsWithWellKnownKey` is off).
    let _ = stages(&mut sim, c, DEV);
    let _ = sim.stack(d).leave(true);
    sim.run_for(Duration::from_secs(2));
    let _ = sim.stack(d).join(JoinMode::TrustCenterRejoin);
    sim.run_for(Duration::from_secs(20));
    let got = stages(&mut sim, c, DEV);
    assert!(
        !got.iter().any(|(s, _)| *s == JoinStage::KeyTransportSent),
        "{got:?}"
    );
}

#[test]
fn removing_a_device_revokes_its_exemption_and_key() {
    let (mut sim, c) = network(tc_config());
    sim.stack(c)
        .grant_commissioning_exemption(DEV, Duration::from_secs(60))
        .unwrap();
    non_exchanging_joiner(&mut sim, c, DEV, 2);
    assert!(
        sim.run_until(Duration::from_secs(60), |x| authorized_events(x, c, DEV)
            > 0)
    );
    sim.run_for(Duration::from_secs(3));
    sim.stack(c).remove_node(DEV, None).unwrap();
    assert!(!sim.stack(c).key_exchange_exempt(DEV));
    assert!(sim.stack(c).aps.security.entry(DEV).is_none());
    assert_eq!(
        sim.stack(c).device_authorization(DEV),
        Authorization::Unknown
    );
}
