//! The hub and the Trust Center authorization policy: devices without
//! application access are not registered or interviewed, administrator
//! exemptions are Admin-only, bounded in time until the device joins,
//! persisted with the device and re-applied after a restart.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod common;

use common::*;
use panweave_hub::diag::code;
use panweave_hub::protocol::frame::{FrameDecoder, MAX_WIRE};
use panweave_hub::protocol::{
    DeviceAuthorization, ErrorCode, Event, Message, Request, Response, SecurityStatus,
};
use panweave_hub::{Access, Session};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{Authorization, JoinMode, StackConfig, StackEvent};
use panweave_security::material::LinkKeyKind;
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{ExtendedAddress, Key128, LogicalDeviceType};

/// A device that never exchanges its link key.
const LEGACY: u64 = 0x00AA_0000_0000_0010;
/// A synthetic, non-production pre-shared key.
const PRESHARED: Key128 = Key128::from_bytes([0xA5; 16]);

/// The hub's network, with dynamic link key negotiation off so a
/// pre-shared-key device must run the link-key exchange.
fn hub_network() -> (Simulator, usize) {
    let (mut sim, c) = network();
    sim.stack(c).config.trust_center_policy.dlk_enabled = false;
    (sim, c)
}

fn legacy_device(sim: &mut Simulator, c: usize) -> usize {
    sim.stack(c).install_link_key(
        ExtendedAddress(LEGACY),
        PRESHARED,
        LinkKeyKind::Unique,
        true,
    );
    let mut cfg = StackConfig::new(LogicalDeviceType::Router, ExtendedAddress(LEGACY));
    cfg.preconfigured_link_key = (ExtendedAddress(HUB), PRESHARED, LinkKeyKind::Unique);
    cfg.model = b"legacy-sim";
    let stack = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(17),
        MemoryStorage::new(),
    );
    let d = sim.add_stack("legacy", stack, Box::new(OnOffApp::default()));
    sim.stack(d).join(JoinMode::Association).unwrap();
    d
}

fn security(sim: &mut Simulator, c: usize) -> SecurityStatus {
    match request(sim, c, &Request::GetSecurityStatus) {
        Response::SecurityStatus(s) => s,
        r => panic!("{r:?}"),
    }
}

fn registered(sim: &mut Simulator, c: usize, ieee: u64) -> bool {
    matches!(
        request(sim, c, &Request::GetDevice { ieee }),
        Response::Device(_)
    )
}

fn trace_has(sim: &mut Simulator, c: usize, code: u16, ieee: u64) -> bool {
    let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    let mut from = 0;
    loop {
        let p = app.hub.read_trace(from, Some(ieee), 12);
        if p.records.is_empty() {
            return false;
        }
        if p.records.iter().any(|r| r.code == code) {
            return true;
        }
        from = p.next;
    }
}

#[test]
fn an_unauthorized_device_is_never_registered() {
    let (mut sim, c) = hub_network();
    let s = security(&mut sim, c);
    assert!(s.require_key_exchange, "secure by default");
    assert_eq!(s.node_join_timeout_s, 15);
    legacy_device(&mut sim, c);
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::KeyExchangeTimedOut { .. }))
    }));
    sim.run_for(Duration::from_secs(5));
    assert!(!registered(&mut sim, c, LEGACY));
    assert!(
        !hub_events(&sim, c)
            .iter()
            .any(|e| matches!(e, Event::DeviceJoined { ieee, .. } if *ieee == LEGACY))
    );
    assert!(trace_has(
        &mut sim,
        c,
        code::JOIN_KEY_EXCHANGE_TIMEOUT,
        LEGACY
    ));
    let s = security(&mut sim, c);
    assert_eq!(s.key_exchange_timeouts, 1);
    // A standard device next to it joins and is interviewed.
    join(&mut sim, c, "bulb", bulb(), BULB);
    assert!(registered(&mut sim, c, BULB));
    assert!(trace_has(&mut sim, c, code::JOIN_AUTHORIZED, BULB));
}

#[test]
fn an_exemption_admits_its_device_and_survives_a_restart() {
    let (mut sim, c) = hub_network();
    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::SetKeyExchangeExemption {
                ieee: LEGACY,
                seconds: 120
            }
        ),
        Response::Done
    );
    let s = security(&mut sim, c);
    assert_eq!(s.exemptions.len(), 1);
    assert!(s.exemptions[0].remaining_s.is_some_and(|r| r > 100));
    legacy_device(&mut sim, c);
    assert!(
        sim.run_until(Duration::from_secs(120), |x| {
            hub_events(x, c).iter().any(
                |e| matches!(e, Event::DeviceInterviewCompleted { ieee, .. } if *ieee == LEGACY),
            )
        }),
        "{:?}",
        hub_events(&sim, c)
    );
    assert!(trace_has(
        &mut sim,
        c,
        code::KEY_EXCHANGE_EXEMPTION_USED,
        LEGACY
    ));
    let s = security(&mut sim, c);
    assert_eq!(s.exemptions.len(), 1);
    assert_eq!(s.exemptions[0].remaining_s, None, "kept with the device");
    assert!(s.unauthorized.is_empty());
    // Restart: the persisted exemption is applied to the stack again.
    let storage = {
        let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
        app.hub.flush();
        app.hub.storage().clone()
    };
    sim.stack(c).clear_key_exchange_exemptions();
    assert_eq!(
        sim.stack(c).device_authorization(ExtendedAddress(LEGACY)),
        Authorization::KeyExchangeIncomplete
    );
    let mut rebooted = HubApp::new(storage);
    assert_eq!(rebooted.hub.restore().unwrap(), 1);
    sim.node_mut(c).app = Box::new(rebooted);
    sim.run_for(Duration::from_secs(1));
    assert_eq!(
        sim.stack(c).device_authorization(ExtendedAddress(LEGACY)),
        Authorization::Exempt
    );
    // Revoked: no application access, the device shows as unauthorized.
    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::SetKeyExchangeExemption {
                ieee: LEGACY,
                seconds: 0
            }
        ),
        Response::Done
    );
    let s = security(&mut sim, c);
    assert!(s.exemptions.is_empty());
    assert_eq!(
        s.unauthorized.as_slice(),
        &[(LEGACY, DeviceAuthorization::KeyExchangeIncomplete)]
    );
}

#[test]
fn an_unused_exemption_expires() {
    let (mut sim, c) = hub_network();
    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::SetKeyExchangeExemption {
                ieee: LEGACY,
                seconds: 5
            }
        ),
        Response::Done
    );
    assert!(
        sim.stack(c)
            .commissioning_exemption(ExtendedAddress(LEGACY))
            .is_some()
    );
    assert!(!sim.stack(c).key_exchange_exempt(ExtendedAddress(LEGACY)));
    sim.run_for(Duration::from_secs(10));
    assert!(
        sim.stack(c)
            .commissioning_exemption(ExtendedAddress(LEGACY))
            .is_none()
    );
    assert!(security(&mut sim, c).exemptions.is_empty());
    assert!(trace_has(
        &mut sim,
        c,
        code::KEY_EXCHANGE_EXEMPTION_EXPIRED,
        LEGACY
    ));
}

#[test]
fn exemption_requests_are_validated_and_admin_only() {
    let (mut sim, c) = hub_network();
    for r in [
        Request::SetKeyExchangeExemption {
            ieee: 0,
            seconds: 10,
        },
        Request::SetKeyExchangeExemption {
            ieee: LEGACY,
            seconds: 3601,
        },
    ] {
        assert_eq!(
            request(&mut sim, c, &r),
            Response::Error(ErrorCode::InvalidArgument)
        );
    }
    // Bounded: grants for devices that are not registered.
    for i in 0..8u64 {
        assert_eq!(
            request(
                &mut sim,
                c,
                &Request::SetKeyExchangeExemption {
                    ieee: 0x5000 + i,
                    seconds: 60
                }
            ),
            Response::Done
        );
    }
    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::SetKeyExchangeExemption {
                ieee: 0x6000,
                seconds: 60
            }
        ),
        Response::Error(ErrorCode::Busy)
    );
    // A Monitor session reads the status but cannot grant.
    let (stack, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    let mut s: Session = Session::new(Access::Monitor);
    for (id, r) in [
        (
            1,
            Request::SetKeyExchangeExemption {
                ieee: LEGACY,
                seconds: 60,
            },
        ),
        (2, Request::GetSecurityStatus),
    ] {
        let mut wire = [0u8; MAX_WIRE];
        let n = Message::Request { id, request: r }
            .encode_frame(&mut wire)
            .unwrap();
        s.receive(&wire[..n], &mut app.hub, stack);
    }
    let mut dec = FrameDecoder::new();
    let mut got = Vec::new();
    s.transmit(|b| {
        if let Some(Ok(body)) = dec.push(b)
            && let Ok(Message::Response { response, .. }) = Message::decode(body)
        {
            got.push(response);
        }
        true
    });
    assert_eq!(got[0], Response::Error(ErrorCode::Unauthorized));
    assert!(matches!(got[1], Response::SecurityStatus(_)));
}

fn exempt(sim: &mut Simulator, c: usize, ieee: u64, seconds: u16) -> Response {
    request(sim, c, &Request::SetKeyExchangeExemption { ieee, seconds })
}

#[test]
fn a_repeated_grant_never_extends_the_window() {
    let (mut sim, c) = hub_network();
    assert_eq!(exempt(&mut sim, c, LEGACY, 600), Response::Done);
    assert_eq!(exempt(&mut sim, c, LEGACY, 10), Response::Done);
    let s = security(&mut sim, c);
    assert_eq!(s.exemptions.len(), 1);
    assert!(s.exemptions[0].remaining_s.is_some_and(|r| r <= 10));
    sim.run_for(Duration::from_secs(15));
    assert!(security(&mut sim, c).exemptions.is_empty());
}

#[test]
fn an_unused_grant_does_not_survive_a_restart() {
    let (mut sim, c) = hub_network();
    assert_eq!(exempt(&mut sim, c, LEGACY, 600), Response::Done);
    let storage = {
        let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
        app.hub.flush();
        app.hub.storage().clone()
    };
    // The hub restarts (its RAM is gone); so does the stack's RAM state.
    sim.stack(c).clear_key_exchange_exemptions();
    let mut rebooted = HubApp::new(storage);
    rebooted.hub.restore().unwrap();
    sim.node_mut(c).app = Box::new(rebooted);
    sim.run_for(Duration::from_secs(1));
    assert!(
        sim.stack(c)
            .commissioning_exemption(ExtendedAddress(LEGACY))
            .is_none()
    );
    assert!(security(&mut sim, c).exemptions.is_empty());
    // The legacy device is now refused.
    legacy_device(&mut sim, c);
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::KeyExchangeTimedOut { .. }))
    }));
    assert!(!registered(&mut sim, c, LEGACY));
}

#[test]
fn a_replayed_grant_for_an_admitted_device_opens_no_new_join_window() {
    let (mut sim, c) = hub_network();
    assert_eq!(exempt(&mut sim, c, LEGACY, 120), Response::Done);
    legacy_device(&mut sim, c);
    assert!(sim.run_until(Duration::from_secs(120), |x| {
        hub_events(x, c)
            .iter()
            .any(|e| matches!(e, Event::DeviceInterviewCompleted { ieee, .. } if *ieee == LEGACY))
    }));
    // The same Admin request again (a replay on the USB link, or a
    // repeated command): the device is registered, it stays admitted,
    // no commissioning window opens for another join.
    assert_eq!(exempt(&mut sim, c, LEGACY, 120), Response::Done);
    assert!(
        sim.stack(c)
            .commissioning_exemption(ExtendedAddress(LEGACY))
            .is_none()
    );
    assert!(sim.stack(c).key_exchange_exempt(ExtendedAddress(LEGACY)));
    // Removing the device revokes everything.
    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::RemoveDevice {
                ieee: LEGACY,
                leave: true
            }
        ),
        Response::Done
    );
    assert!(!sim.stack(c).key_exchange_exempt(ExtendedAddress(LEGACY)));
    assert!(security(&mut sim, c).exemptions.is_empty());
}
