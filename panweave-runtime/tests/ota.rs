//! OTA upgrade end to end (ZCL8 chapter 11): a router client polls the
//! coordinator's upgrade server, downloads a 300-octet image in blocks
//! over the air with the server rate-limiting the first request, verifies
//! it, sends the Upgrade End Request and receives the upgrade time.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::option_option
)]

use panweave_aps::layer::Destination;
use panweave_codec::Writer;
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
use panweave_zcl::frame::{Direction, FrameType, ZclStatus};
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

const NETWORK_KEY: panweave_types::Key128 = panweave_types::Key128::from_bytes([0x5A; 16]);
const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const ROUTER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0003);
const EP: Endpoint = Endpoint(1);
const IMAGE_LEN: usize = 300;

struct MemImage {
    header: ota::Header,
    bytes: Vec<u8>,
}

impl ota::ImageSource for MemImage {
    fn header(&self) -> ota::Header {
        self.header
    }
    fn read(&self, offset: u32, out: &mut [u8]) -> usize {
        let start = (offset as usize).min(self.bytes.len());
        let n = out.len().min(self.bytes.len() - start);
        out[..n].copy_from_slice(&self.bytes[start..start + n]);
        n
    }
}

fn image() -> MemImage {
    let mut header = ota::Header {
        version: ota::HEADER_VERSION,
        length: 56,
        field_control: 0,
        manufacturer_code: 0x1234,
        image_type: 1,
        file_version: 0x0200_0000,
        stack_version: 2,
        string: [0; 32],
        total_size: IMAGE_LEN as u32,
        security_credential_version: None,
        destination: None,
        hardware_versions: None,
    };
    let mut bytes = vec![0u8; IMAGE_LEN];
    let n = header.encode(&mut bytes).unwrap();
    assert_eq!(n, 56);
    let body = IMAGE_LEN - 56 - 6;
    bytes[56..58].copy_from_slice(&ota::tag::UPGRADE_IMAGE.to_le_bytes());
    bytes[58..62].copy_from_slice(&(body as u32).to_le_bytes());
    for (i, b) in bytes[62..].iter_mut().enumerate() {
        *b = (i * 7) as u8;
    }
    header.total_size = IMAGE_LEN as u32;
    MemImage { header, bytes }
}

fn node(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = true;
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
    let mut ep = EndpointInstance::new(EP, ProfileId::HOME_AUTOMATION);
    ep.add_instance(identify::server().unwrap()).unwrap();
    let (servers, clients): (&[ClusterId], &[ClusterId]) = if role == LogicalDeviceType::Coordinator
    {
        ep.add_instance(ota::server()).unwrap();
        (&[ClusterId(0), identify::ID, ota::ID], &[identify::ID])
    } else {
        ep.add_instance(ota::client(&client_config(), COORD_IEEE).unwrap())
            .unwrap();
        (&[ClusterId(0), identify::ID], &[identify::ID, ota::ID])
    };
    let desc = SimpleDescriptor::new(
        EP,
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0005),
        1,
        servers,
        clients,
    )
    .unwrap();
    n.add_endpoint(desc, ep).unwrap();
    n
}

fn client_config() -> ota::ClientConfig {
    ota::ClientConfig {
        manufacturer_code: 0x1234,
        image_type: 1,
        file_version: 0x0100_0000,
        hardware_version: None,
        max_data_size: 48,
        activation_policy: ota::activation_policy::SERVER,
    }
}

/// The upgrade server: answers queries and block requests from one image
/// and tells the first block request to wait 2 s with a 100 ms rate limit.
struct ServerApp {
    image: MemImage,
    waited: bool,
    end_request: Option<ota::UpgradeEndRequest>,
}

impl App for ServerApp {
    fn on_event(&mut self, stack: &mut SimStack, event: &StackEvent) {
        let StackEvent::ZclCommand(f) = event else {
            return;
        };
        if f.origin.cluster != ota::ID || f.origin.header.control.direction != Direction::ToServer {
            return;
        }
        let origin = f.origin;
        let mut out = [0u8; 96];
        let images: [&dyn ota::ImageSource; 1] = [&self.image];
        match f.origin.header.command {
            ota::CMD_QUERY_NEXT_IMAGE_REQUEST => {
                let req = ota::QueryNextImageRequest::parse(&f.payload).unwrap();
                let rsp = ota::query_response(&req, ROUTER_IEEE, &images);
                let mut w = Writer::new(&mut out);
                rsp.encode(&mut w).unwrap();
                let n = w.position();
                stack
                    .zcl
                    .respond(
                        &origin,
                        ota::CMD_QUERY_NEXT_IMAGE_RESPONSE,
                        FrameType::ClusterSpecific,
                        &out[..n],
                    )
                    .unwrap();
            }
            ota::CMD_IMAGE_BLOCK_REQUEST => {
                let req = ota::ImageBlockRequest::parse(&f.payload).unwrap();
                let rsp = if self.waited {
                    let mut data = [0u8; 64];
                    let r = ota::block_response(&req, &images, 40, &mut data);
                    let mut w = Writer::new(&mut out);
                    r.encode(&mut w).unwrap();
                    w.position()
                } else {
                    self.waited = true;
                    let r = ota::ImageBlockResponse::WaitForData {
                        current_time: 0,
                        request_time: 2,
                        minimum_block_period: 100,
                    };
                    let mut w = Writer::new(&mut out);
                    r.encode(&mut w).unwrap();
                    w.position()
                };
                stack
                    .zcl
                    .respond(
                        &origin,
                        ota::CMD_IMAGE_BLOCK_RESPONSE,
                        FrameType::ClusterSpecific,
                        &out[..rsp],
                    )
                    .unwrap();
            }
            ota::CMD_UPGRADE_END_REQUEST => {
                let req = ota::UpgradeEndRequest::parse(&f.payload).unwrap();
                self.end_request = Some(req);
                if req.status == ZclStatus::Success {
                    let rsp = ota::UpgradeEndResponse {
                        image: req.image,
                        current_time: 0,
                        upgrade_time: 10,
                    };
                    let mut w = Writer::new(&mut out);
                    rsp.encode(&mut w).unwrap();
                    let n = w.position();
                    stack
                        .zcl
                        .respond(
                            &origin,
                            ota::CMD_UPGRADE_END_RESPONSE,
                            FrameType::ClusterSpecific,
                            &out[..n],
                        )
                        .unwrap();
                } else {
                    stack
                        .zcl
                        .default_response(&origin, ZclStatus::Success)
                        .unwrap();
                }
            }
            _ => {
                stack
                    .zcl
                    .default_response(&origin, ZclStatus::UnsupportedClusterCommand)
                    .unwrap();
            }
        }
    }
}

/// The upgrading device: drives the client machine, stores the blocks
/// and verifies the file against its header.
struct ClientApp {
    client: ota::Client,
    received: Vec<u8>,
    pending: Option<(ota::ImageBlockRequest, Instant)>,
    upgrade_at: Option<Option<Instant>>,
    blocks: usize,
}

impl ClientApp {
    fn send(stack: &mut SimStack, cmd: CommandId, payload: &[u8]) {
        stack
            .zcl
            .send_command(
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
            )
            .unwrap();
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
            } => {
                self.pending = Some((request, not_before));
            }
            ota::ClientAction::Store { offset, data } => {
                assert_eq!(offset as usize, self.received.len());
                self.received.extend_from_slice(data);
                self.blocks += 1;
                let next = self.client.next(stack.now());
                self.act(stack, next);
            }
            ota::ClientAction::Verify { size, .. } => {
                assert_eq!(size as usize, self.received.len());
                let ok = ota::Header::parse(&self.received).is_ok();
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
            ota::ClientAction::Default(status) => panic!("unexpected default response {status:?}"),
            ota::ClientAction::None => {}
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
        match f.origin.header.command {
            ota::CMD_QUERY_NEXT_IMAGE_RESPONSE => {
                let r = ota::QueryNextImageResponse::parse(&f.payload).unwrap();
                let a = self.client.on_query_response(&r, now);
                self.act(stack, a);
            }
            ota::CMD_IMAGE_BLOCK_RESPONSE => {
                let r = ota::ImageBlockResponse::parse(&f.payload).unwrap();
                let a = self.client.on_block_response(&r, now);
                self.act(stack, a);
            }
            ota::CMD_UPGRADE_END_RESPONSE => {
                let r = ota::UpgradeEndResponse::parse(&f.payload).unwrap();
                let a = self.client.on_upgrade_end_response(&r, now);
                self.act(stack, a);
            }
            _ => {}
        }
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

#[test]
fn client_downloads_verifies_and_is_told_when_to_upgrade() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "server",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 41),
        Box::new(ServerApp {
            image: image(),
            waited: false,
            end_request: None,
        }),
    );
    let r = sim.add_stack(
        "client",
        node(LogicalDeviceType::Router, ROUTER_IEEE, 42),
        Box::new(ClientApp {
            client: ota::Client::new(client_config()),
            received: Vec::new(),
            pending: None,
            upgrade_at: None,
            blocks: 0,
        }),
    );
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(180).unwrap();
    sim.stack(r).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::Joined { .. }))
    }));
    sim.run_for(Duration::from_secs(2));
    let start = sim.clock.now();
    {
        let (stack, app) = sim.stack_and_app::<ClientApp>(r).unwrap();
        let a = app.client.start_query();
        app.act(stack, a);
    }
    assert!(
        sim.run_until(Duration::from_secs(60), |x| {
            x.app::<ClientApp>(r).unwrap().upgrade_at.is_some()
        }),
        "phase {:?}, {} bytes",
        sim.app::<ClientApp>(r).unwrap().client.phase,
        sim.app::<ClientApp>(r).unwrap().received.len()
    );
    let client = sim.app::<ClientApp>(r).unwrap();
    let server = sim.app::<ServerApp>(c).unwrap();
    assert_eq!(client.received, server.image.bytes);
    assert_eq!(client.blocks, IMAGE_LEN.div_ceil(40));
    assert_eq!(server.end_request.unwrap().status, ZclStatus::Success);
    let at = client.upgrade_at.unwrap().unwrap();
    // The wait (2 s) came before the first block.
    assert!(at.as_millis() >= start.as_millis() + 12_000);
    assert_eq!(
        client.client.upgrade_status(),
        ota::upgrade_status::COUNT_DOWN
    );
    let cl = sim
        .stack(r)
        .zcl
        .cluster(EP, ota::ID, panweave_zcl::Role::Client)
        .unwrap();
    assert_eq!(
        cl.u8(ota::IMAGE_UPGRADE_STATUS.id),
        Some(ota::upgrade_status::COUNT_DOWN)
    );
    assert_eq!(cl.u64(ota::DOWNLOADED_FILE_VERSION.id), Some(0x0200_0000));
}
