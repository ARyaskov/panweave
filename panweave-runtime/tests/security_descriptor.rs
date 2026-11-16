//! Negotiated credentials retain their token, lock and provenance across
//! real stack restarts; legacy records migrate conservatively.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_codec::{Decode, Writer};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, Restored, StackConfig, StackEvent};
use panweave_security::material::{
    InitialJoinAuthentication, KeyNegotiationState, LinkKeyEntry, PostJoinKeyUpdate,
};
use panweave_security::trust_center::{InstallCodePolicy, TclkRequestPolicy, TrustCenterPolicy};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::{Key, Kind, MemoryStorage, Storage, StorageError};
use panweave_testkit::TestRng;
use panweave_types::{Duration, ExtendedAddress, Key128, LogicalDeviceType, ShortAddress};
use panweave_zdo::security::{
    AuthenticationTokenId, RetrieveAuthenticationTokenReq, RetrieveAuthenticationTokenRsp,
    SelectedKeyNegotiationMethod, StartKeyUpdateReq,
};
use panweave_zdo::{ZdpStatus, cluster};

const TC: ExtendedAddress = ExtendedAddress(0x00EA_0000_0000_0001);
const ROUTER: ExtendedAddress = ExtendedAddress(0x00EA_0000_0000_0002);
type Mem = MemoryStorage<64, 128>;

fn stack(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64, storage: Mem) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = true;
    cfg.trust_center_policy.install_codes = InstallCodePolicy::OptionalWithAnonymousNegotiation;
    SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        storage,
    )
}

fn negotiated_pair() -> (Simulator, usize, usize) {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "tc",
        stack(LogicalDeviceType::Coordinator, TC, 1, Mem::new()),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c)
        .form_network_with_key(Key128::from_bytes([0x77; 16]))
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |s| {
        s.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(180).unwrap();
    let r = sim.add_stack(
        "router",
        stack(LogicalDeviceType::Router, ROUTER, 2, Mem::new()),
        Box::new(OnOffApp::default()),
    );
    sim.stack(r).join(JoinMode::Association).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(60), |s| s
            .events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::AuthenticationTokenStored))),
        "{:?}",
        sim.events(r)
    );
    sim.run_for(Duration::from_secs(1));
    let tc = sim.stack(c).aps.security.entry(ROUTER).unwrap().clone();
    let router = sim.stack(r).aps.security.entry(TC).unwrap();
    assert_eq!(tc.key, router.key);
    assert!(tc.passphrase.is_some());
    assert_eq!(tc.passphrase, router.passphrase);
    assert!(!tc.passphrase_update_allowed);
    assert!(!router.passphrase_update_allowed);
    (sim, c, r)
}

fn assert_metadata(entry: &LinkKeyEntry, expected: &LinkKeyEntry) {
    assert_eq!(entry.key, expected.key);
    assert_eq!(entry.kind, expected.kind);
    assert_eq!(entry.attributes, expected.attributes);
    assert_eq!(
        entry.initial_join_authentication,
        expected.initial_join_authentication
    );
    assert_eq!(entry.negotiation_state, expected.negotiation_state);
    assert_eq!(entry.negotiation_method, expected.negotiation_method);
    assert_eq!(entry.post_join_key_update, expected.post_join_key_update);
    assert_eq!(entry.passphrase, expected.passphrase);
    assert_eq!(
        entry.passphrase_update_allowed,
        expected.passphrase_update_allowed
    );
    assert_eq!(entry.frame_counter_sync, expected.frame_counter_sync);
    assert!(!entry.verified_frame_counter);
    assert_eq!(entry.challenge_frame_counter, 0);
    assert_eq!(entry.timeout_secs, 0xffff);
}

fn stored_key(storage: &mut Mem, partner: ExtendedAddress) -> Vec<u8> {
    let mut buf = [0; 128];
    let n = storage
        .load(Key::with_id(Kind::LinkKey, partner.0), &mut buf)
        .unwrap()
        .unwrap();
    buf[..n].to_vec()
}

#[test]
fn token_lock_and_authenticated_renegotiation_survive_both_peers_rebooting() {
    let (mut sim, c, r) = negotiated_pair();
    let expected_c = sim.stack(c).aps.security.entry(ROUTER).unwrap().clone();
    let expected_r = sim.stack(r).aps.security.entry(TC).unwrap().clone();
    let cstore = sim.stack(c).storage.clone();
    let rstore = sim.stack(r).storage.clone();
    // Rely on the actual token handlers' persistence actions, without
    // calling persist_link_keys to repair their output in the fixture.
    sim.isolate(c);
    sim.isolate(r);
    let mut fresh_c = stack(LogicalDeviceType::Coordinator, TC, 3, cstore);
    let mut fresh_r = stack(LogicalDeviceType::Router, ROUTER, 4, rstore);
    assert_eq!(fresh_c.restore().unwrap(), Restored::OnNetwork);
    assert_eq!(fresh_r.restore().unwrap(), Restored::OnNetwork);
    assert_metadata(fresh_c.aps.security.entry(ROUTER).unwrap(), &expected_c);
    assert_metadata(fresh_r.aps.security.entry(TC).unwrap(), &expected_r);
    fresh_c.poll(sim.clock.now());
    fresh_r.poll(sim.clock.now());
    fresh_c.resume().unwrap();
    fresh_r.resume().unwrap();
    let c2 = sim.add_stack("tc2", fresh_c, Box::new(OnOffApp::default()));
    let r2 = sim.add_stack("router2", fresh_r, Box::new(OnOffApp::default()));
    for old in [c, r] {
        for new in [c2, r2] {
            sim.block(old, new);
        }
    }
    sim.run_for(Duration::from_secs(3));

    let mut tlvs = [0u8; 3];
    let mut writer = Writer::new(&mut tlvs);
    AuthenticationTokenId(panweave_nwk::tlv::tag::SYMMETRIC_PASSPHRASE)
        .write(&mut writer)
        .unwrap();
    let request = RetrieveAuthenticationTokenReq { tlvs: &tlvs };
    let mut denied = false;
    // The first secured request may synchronize rebooted peers' counters
    // and time out; retries still traverse the real radio and ZDO path.
    for _ in 0..3 {
        sim.take_events(r2);
        sim.stack(r2)
            .zdo
            .request_secured(
                ShortAddress::COORDINATOR,
                cluster::SECURITY_RETRIEVE_AUTHENTICATION_TOKEN_REQ,
                &request,
            )
            .unwrap();
        sim.stack(r2).flush();
        denied = sim.run_until(Duration::from_secs(20), |s| {
            s.events(r2).iter().any(|e| match e {
                StackEvent::Zdp(z)
                    if z.cluster
                        == cluster::response_of(
                            cluster::SECURITY_RETRIEVE_AUTHENTICATION_TOKEN_REQ,
                        ) =>
                {
                    RetrieveAuthenticationTokenRsp::decode_exact(&z.data)
                        .is_ok_and(|rsp| rsp.status == ZdpStatus::NotPermitted)
                }
                _ => false,
            })
        });
        if denied {
            break;
        }
    }
    assert!(
        denied,
        "reboot must not unlock token retrieval: {:?}",
        sim.events(r2)
    );
    assert!(
        sim.stack(c2)
            .aps
            .security
            .entry(ROUTER)
            .unwrap()
            .verified_frame_counter
    );
    assert!(
        sim.stack(r2)
            .aps
            .security
            .entry(TC)
            .unwrap()
            .verified_frame_counter
    );

    sim.take_events(c2);
    sim.take_events(r2);
    let method = SelectedKeyNegotiationMethod {
        protocol: SelectedKeyNegotiationMethod::PROTOCOL_SPEKE_AES_MMO,
        secret: SelectedKeyNegotiationMethod::SECRET_AUTH_TOKEN,
        sender: TC,
    };
    let mut tlvs = [0u8; 12];
    method.write(&mut Writer::new(&mut tlvs)).unwrap();
    let target = sim.stack(r2).short_address();
    sim.stack(c2)
        .zdo
        .request_secured(
            target,
            cluster::SECURITY_START_KEY_UPDATE_REQ,
            &StartKeyUpdateReq { tlvs: &tlvs },
        )
        .unwrap();
    sim.stack(c2).flush();
    assert!(
        sim.run_until(Duration::from_secs(30), |s| s
            .events(r2)
            .iter()
            .any(|e| matches!(e, StackEvent::LinkKeyUpdated))),
        "{:?}",
        sim.events(r2)
    );
    let renewed_c = sim.stack(c2).aps.security.entry(ROUTER).unwrap().clone();
    let renewed_r = sim.stack(r2).aps.security.entry(TC).unwrap().clone();
    assert_eq!(renewed_c.key, renewed_r.key);
    assert_ne!(renewed_c.key, expected_c.key);
    for entry in [&renewed_c, &renewed_r] {
        assert_eq!(entry.negotiation_state, KeyNegotiationState::Complete);
        assert_eq!(
            entry.post_join_key_update,
            PostJoinKeyUpdate::AuthenticatedNegotiation
        );
        assert_eq!(entry.passphrase, expected_c.passphrase);
        assert!(!entry.passphrase_update_allowed);
    }
}

#[test]
fn legacy_key_records_keep_traffic_material_and_migrate_without_reopening_security() {
    let (mut sim, c, _r) = negotiated_pair();
    let expected = sim.stack(c).aps.security.entry(ROUTER).unwrap().clone();
    let mut storage = sim.stack(c).storage.clone();
    let mut legacy = stored_key(&mut storage, ROUTER);
    legacy.truncate(36);
    legacy[0] = 1;
    storage
        .store(Key::with_id(Kind::LinkKey, ROUTER.0), &legacy)
        .unwrap();
    let mut fresh = stack(LogicalDeviceType::Coordinator, TC, 5, storage);
    assert_eq!(fresh.restore().unwrap(), Restored::OnNetwork);
    let entry = fresh.aps.security.entry(ROUTER).unwrap();
    assert_eq!(entry.key, expected.key);
    assert_eq!(entry.attributes, expected.attributes);
    assert!(entry.outgoing.peek() >= expected.outgoing.peek());
    assert!(!entry.passphrase_update_allowed);
    assert!(entry.passphrase.is_none());
    assert_eq!(
        entry.initial_join_authentication,
        InitialJoinAuthentication::None
    );
    assert_eq!(entry.post_join_key_update, PostJoinKeyUpdate::NotUpdated);
    let policy = TrustCenterPolicy {
        tclk_requests: TclkRequestPolicy::Any,
        ..TrustCenterPolicy::default()
    };
    assert!(!policy.allow_tclk_request(Some(entry), true));
    fresh.persist_link_keys().unwrap();
    assert_eq!(stored_key(&mut fresh.storage, ROUTER)[0], 2);
    let mut again = stack(LogicalDeviceType::Coordinator, TC, 6, fresh.storage);
    assert_eq!(again.restore().unwrap(), Restored::OnNetwork);
    let entry = again.aps.security.entry(ROUTER).unwrap();
    assert!(!entry.passphrase_update_allowed);
    assert!(!policy.allow_tclk_request(Some(entry), true));
}

#[test]
fn malformed_security_descriptors_fail_closed_and_volatile_fields_restart() {
    let (mut sim, c, _r) = negotiated_pair();
    let original = sim.stack(c).storage.clone();
    let mut storage = original.clone();
    let valid = stored_key(&mut storage, ROUTER);
    let mut bad_initial = valid.clone();
    bad_initial[36] = 255;
    let mut bad_lock = valid.clone();
    bad_lock[40] = 2;
    let mut bad_partner = valid.clone();
    bad_partner[1] ^= 1;
    let mut trailing = valid.clone();
    trailing.push(0);
    for damaged in [
        valid[..36].to_vec(),
        bad_initial,
        bad_lock,
        bad_partner,
        trailing,
    ] {
        let mut storage = original.clone();
        storage
            .store(Key::with_id(Kind::LinkKey, ROUTER.0), &damaged)
            .unwrap();
        let writes = storage.writes;
        let mut fresh = stack(LogicalDeviceType::Coordinator, TC, 7, storage);
        assert_eq!(fresh.restore(), Err(StorageError::Corrupt));
        assert!(!fresh.is_operating());
        assert_eq!(fresh.storage.writes, writes);
    }
    let entry = sim
        .stack(c)
        .aps
        .security
        .keys_mut()
        .get_mut(ROUTER)
        .unwrap();
    entry.timeout_secs = 5;
    entry.challenge_frame_counter = 42;
    sim.stack(c).persist_link_keys().unwrap();
    let mut fresh = stack(
        LogicalDeviceType::Coordinator,
        TC,
        8,
        sim.stack(c).storage.clone(),
    );
    fresh.restore().unwrap();
    let entry = fresh.aps.security.entry(ROUTER).unwrap();
    assert_eq!(entry.timeout_secs, 0xffff);
    assert_eq!(entry.challenge_frame_counter, 0);
    assert!(!entry.verified_frame_counter);
}
