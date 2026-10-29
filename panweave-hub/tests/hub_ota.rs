//! The hub as OTA upgrade server: a router running the OTA client
//! machine downloads an image the host offers and streams on demand,
//! through the hub's sliding window; offers that do not suit are not
//! served, and a cancelled offer aborts the download.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::option_option
)]

mod common;

use common::*;
use panweave_aps::layer::Destination;
use panweave_codec::Writer;
use panweave_hub::protocol::{
    ErrorCode, Event, MAX_OTA_CHUNK, OtaImage, OtaOffer, Request, Response,
};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{App, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    ClusterId, CommandId, DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId,
    ShortAddress,
};
use panweave_zcl::clusters::{identify, ota};
use panweave_zcl::frame::{Direction, ZclStatus};
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

const DEVICE: u64 = 0x00AA_0000_0000_0030;
const EP: Endpoint = Endpoint(1);
const IMAGE_LEN: usize = 3000;
const MANUFACTURER: u16 = 0x1234;
const OLD: u32 = 0x0100_0000;
const NEW: u32 = 0x0200_0000;

/// A valid OTA file: header, one upgrade-image element, patterned data.
fn image_file() -> Vec<u8> {
    let header = ota::Header {
        version: ota::HEADER_VERSION,
        length: 56,
        field_control: 0,
        manufacturer_code: MANUFACTURER,
        image_type: 1,
        file_version: NEW,
        stack_version: 2,
        string: [0; 32],
        total_size: IMAGE_LEN as u32,
        security_credential_version: None,
        destination: None,
        hardware_versions: None,
    };
    let mut bytes = vec![0u8; IMAGE_LEN];
    assert_eq!(header.encode(&mut bytes).unwrap(), 56);
    let body = IMAGE_LEN - 56 - 6;
    bytes[56..58].copy_from_slice(&ota::tag::UPGRADE_IMAGE.to_le_bytes());
    bytes[58..62].copy_from_slice(&(body as u32).to_le_bytes());
    for (i, b) in bytes[62..].iter_mut().enumerate() {
        *b = (i * 7 + i / 251) as u8;
    }
    bytes
}

fn offer(target: Option<u64>) -> OtaOffer {
    OtaOffer {
        image: OtaImage {
            manufacturer_code: MANUFACTURER,
            image_type: 1,
            file_version: NEW,
            size: IMAGE_LEN as u32,
        },
        target,
        allow_downgrade: false,
    }
}

fn client_config() -> ota::ClientConfig {
    ota::ClientConfig {
        manufacturer_code: MANUFACTURER,
        image_type: 1,
        file_version: OLD,
        hardware_version: None,
        max_data_size: 48,
        activation_policy: ota::activation_policy::SERVER,
    }
}

/// The upgrading device: drives the client machine and stores blocks.
struct ClientApp {
    client: ota::Client,
    received: Vec<u8>,
    pending: Option<(ota::ImageBlockRequest, Instant)>,
    upgrade_at: Option<Option<Instant>>,
    no_image: usize,
}

impl ClientApp {
    fn send(stack: &mut SimStack, cmd: CommandId, payload: &[u8]) {
        let _ = stack.zcl.send_command(
            Destination::Short {
                address: ShortAddress::COORDINATOR,
                endpoint: EP,
            },
            ProfileId::HOME_AUTOMATION,
            ota::ID,
            EP,
            cmd,
            Direction::ToServer,
            None,
            payload,
        );
    }

    fn act(&mut self, stack: &mut SimStack, action: ota::ClientAction<'_>) {
        let mut buf = [0u8; 32];
        match action {
            ota::ClientAction::Query(q) => {
                let mut w = Writer::new(&mut buf);
                q.encode(&mut w).unwrap();
                let n = w.position();
                Self::send(stack, ota::CMD_QUERY_NEXT_IMAGE_REQUEST, &buf[..n]);
            }
            ota::ClientAction::RequestBlock {
                request,
                not_before,
            } => self.pending = Some((request, not_before)),
            ota::ClientAction::Store { offset, data } => {
                assert_eq!(offset as usize, self.received.len());
                self.received.extend_from_slice(data);
                let next = self.client.next(stack.now());
                self.act(stack, next);
            }
            ota::ClientAction::Verify { size, .. } => {
                let ok = size as usize == self.received.len()
                    && ota::Header::parse(&self.received).is_ok();
                let a = self.client.finish(if ok {
                    ZclStatus::Success
                } else {
                    ZclStatus::InvalidImage
                });
                self.act(stack, a);
            }
            ota::ClientAction::UpgradeEnd(req) => {
                let mut w = Writer::new(&mut buf);
                req.encode(&mut w).unwrap();
                let n = w.position();
                Self::send(stack, ota::CMD_UPGRADE_END_REQUEST, &buf[..n]);
            }
            ota::ClientAction::Upgrade { at, .. } => self.upgrade_at = Some(at),
            ota::ClientAction::Default(_) | ota::ClientAction::None => {}
        }
        if let Some(c) = stack
            .zcl
            .cluster_mut(EP, ota::ID, panweave_zcl::Role::Client)
        {
            self.client.publish(c);
        }
    }
}

impl App for ClientApp {
    fn on_event(&mut self, stack: &mut SimStack, event: &StackEvent) {
        let StackEvent::ZclCommand(f) = event else {
            return;
        };
        if f.origin.cluster != ota::ID || f.origin.header.control.direction != Direction::ToClient {
            return;
        }
        let now = stack.now();
        let a = match f.origin.header.command {
            ota::CMD_QUERY_NEXT_IMAGE_RESPONSE => {
                let r = ota::QueryNextImageResponse::parse(&f.payload).unwrap();
                if r.status == ZclStatus::NoImageAvailable {
                    self.no_image += 1;
                }
                self.client.on_query_response(&r, now)
            }
            ota::CMD_IMAGE_BLOCK_RESPONSE => {
                let r = ota::ImageBlockResponse::parse(&f.payload).unwrap();
                self.client.on_block_response(&r, now)
            }
            ota::CMD_UPGRADE_END_RESPONSE => {
                let r = ota::UpgradeEndResponse::parse(&f.payload).unwrap();
                self.client.on_upgrade_end_response(&r, now)
            }
            _ => return,
        };
        self.act(stack, a);
    }

    fn on_poll(&mut self, stack: &mut SimStack, now: Instant) {
        if let Some((req, not_before)) = self.pending
            && now.has_reached(not_before)
        {
            self.pending = None;
            let mut buf = [0u8; 32];
            let mut w = Writer::new(&mut buf);
            req.encode(&mut w).unwrap();
            let n = w.position();
            Self::send(stack, ota::CMD_IMAGE_BLOCK_REQUEST, &buf[..n]);
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.pending.map(|(_, t)| t)
    }
}

/// A router with an OTA client, joined and interviewed by the hub.
fn upgradable(sim: &mut Simulator, c: usize) -> usize {
    let mut cfg = StackConfig::new(LogicalDeviceType::Router, ExtendedAddress(DEVICE));
    cfg.manufacturer_name = b"Sim Devices";
    cfg.model = b"ota-sim";
    let mut s = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(30),
        MemoryStorage::new(),
    );
    let mut ep = EndpointInstance::new(EP, ProfileId::HOME_AUTOMATION);
    ep.add_instance(identify::server().unwrap()).unwrap();
    ep.add_instance(ota::client(&client_config(), ExtendedAddress(HUB)).unwrap())
        .unwrap();
    let desc = SimpleDescriptor::new(
        EP,
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0100),
        1,
        &[ClusterId(0), identify::ID],
        &[identify::ID, ota::ID],
    )
    .unwrap();
    s.add_endpoint(desc, ep).unwrap();
    let d = sim.add_stack(
        "device",
        s,
        Box::new(ClientApp {
            client: ota::Client::new(client_config()),
            received: Vec::new(),
            pending: None,
            upgrade_at: None,
            no_image: 0,
        }),
    );
    sim.stack(d).join(JoinMode::Association).unwrap();
    wait_event(
        sim,
        c,
        180,
        |e| matches!(e, Event::DeviceInterviewCompleted { ieee, .. } if *ieee == DEVICE),
    );
    d
}

fn query(sim: &mut Simulator, d: usize) {
    let (stack, app) = sim.stack_and_app::<ClientApp>(d).unwrap();
    let a = app.client.start_query();
    app.act(stack, a);
}

/// Plays the host for `secs` seconds or until `done`: answers every
/// OtaDataWanted from `file`. Returns the hub's events.
fn serve(
    sim: &mut Simulator,
    c: usize,
    file: &[u8],
    secs: u64,
    done: impl Fn(&Simulator) -> bool,
) -> Vec<Event> {
    let mut all = Vec::new();
    for _ in 0..secs {
        sim.run_until(Duration::from_secs(1), |x| {
            done(x)
                || hub_events(x, c)
                    .iter()
                    .any(|e| matches!(e, Event::OtaDataWanted { .. }))
        });
        for e in take_hub_events(sim, c) {
            if let Event::OtaDataWanted { offset, length } = e {
                let end = (offset as usize + usize::from(length)).min(file.len());
                let mut at = offset as usize;
                while at < end {
                    let n = (end - at).min(MAX_OTA_CHUNK);
                    let r = request(
                        sim,
                        c,
                        &Request::OtaData {
                            offset: at as u32,
                            data: heapless::Vec::from_slice(&file[at..at + n]).unwrap(),
                        },
                    );
                    assert_eq!(r, Response::Done);
                    at += n;
                }
            }
            all.push(e);
        }
        if done(sim) {
            break;
        }
    }
    all
}

fn client(sim: &Simulator, d: usize) -> &ClientApp {
    sim.app::<ClientApp>(d).unwrap()
}

#[test]
fn a_device_downloads_the_offered_image_through_the_window() {
    let (mut sim, c) = network();
    let d = upgradable(&mut sim, c);
    let file = image_file();
    assert_eq!(
        request(&mut sim, c, &Request::OtaOffer(offer(None))),
        Response::Done
    );
    query(&mut sim, d);
    let events = serve(&mut sim, c, &file, 300, |x| {
        client(x, d).upgrade_at.is_some()
    });
    let app = client(&sim, d);
    assert!(app.upgrade_at.is_some(), "phase {:?}", app.client.phase);
    assert_eq!(app.received, file);
    // Told to upgrade now.
    assert_eq!(app.upgrade_at, Some(Some(app.upgrade_at.unwrap().unwrap())));
    assert!(events.contains(&Event::OtaFinished {
        ieee: DEVICE,
        status: 0
    }));
    // The window slid: the data came in several requests, and progress
    // was reported up to the end.
    let wanted = events
        .iter()
        .filter(|e| matches!(e, Event::OtaDataWanted { .. }))
        .count();
    assert!(wanted >= 3, "{wanted} data requests");
    assert!(events.contains(&Event::OtaProgress {
        ieee: DEVICE,
        offset: IMAGE_LEN as u32,
        size: IMAGE_LEN as u32
    }));
    match request(&mut sim, c, &Request::GetOtaStatus) {
        Response::OtaStatus(s) => {
            assert_eq!(s.device, None);
            assert_eq!(s.offer, Some(offer(None)));
        }
        r => panic!("{r:?}"),
    }
}

#[test]
fn offers_that_do_not_suit_the_device_are_not_served() {
    let (mut sim, c) = network();
    let d = upgradable(&mut sim, c);
    let file = image_file();
    let mut not_newer = offer(None);
    not_newer.image.file_version = OLD;
    let mut other_maker = offer(None);
    other_maker.image.manufacturer_code = 0x9999;
    for (i, o) in [not_newer, other_maker, offer(Some(0x00AA_0000_0000_00FF))]
        .into_iter()
        .enumerate()
    {
        assert_eq!(request(&mut sim, c, &Request::OtaOffer(o)), Response::Done);
        query(&mut sim, d);
        let events = serve(&mut sim, c, &file, 10, |x| client(x, d).no_image > i);
        assert_eq!(client(&sim, d).no_image, i + 1, "offer {i}");
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, Event::OtaProgress { .. } | Event::OtaFinished { .. })),
            "offer {i}: {events:?}"
        );
    }
    assert!(client(&sim, d).received.is_empty());
}

#[test]
fn a_cancelled_offer_aborts_the_download() {
    let (mut sim, c) = network();
    let d = upgradable(&mut sim, c);
    let file = image_file();
    request(&mut sim, c, &Request::OtaOffer(offer(Some(DEVICE))));
    query(&mut sim, d);
    serve(&mut sim, c, &file, 300, |x| {
        client(x, d).received.len() > 1000
    });
    assert!(client(&sim, d).received.len() > 1000);
    assert_eq!(request(&mut sim, c, &Request::OtaCancel), Response::Done);
    assert!(take_hub_events(&mut sim, c).contains(&Event::OtaFinished {
        ieee: DEVICE,
        status: 0x95
    }));
    let got = client(&sim, d).received.len();
    sim.run_for(Duration::from_secs(30));
    let app = client(&sim, d);
    assert!(app.upgrade_at.is_none());
    assert!(app.received.len() < IMAGE_LEN && app.received.len() <= got + 48);
}

#[test]
fn bad_offers_and_data_are_refused() {
    let (mut sim, c) = network();
    // Data without an offer.
    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::OtaData {
                offset: 0,
                data: heapless::Vec::from_slice(&[1, 2, 3]).unwrap(),
            }
        ),
        Response::Error(ErrorCode::InvalidArgument)
    );
    // An image smaller than a header.
    let mut tiny = offer(None);
    tiny.image.size = 10;
    assert_eq!(
        request(&mut sim, c, &Request::OtaOffer(tiny)),
        Response::Error(ErrorCode::InvalidArgument)
    );
    request(&mut sim, c, &Request::OtaOffer(offer(None)));
    // Not where the window ends, or past the image.
    for (offset, n) in [(100u32, 4usize), (IMAGE_LEN as u32 - 2, 4)] {
        assert_eq!(
            request(
                &mut sim,
                c,
                &Request::OtaData {
                    offset,
                    data: heapless::Vec::from_slice(&vec![0u8; n]).unwrap(),
                }
            ),
            Response::Error(ErrorCode::InvalidArgument)
        );
    }
}
