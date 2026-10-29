//! The hub as OTA upgrade server (ZCL8 chapter 11) for one image offered
//! by the host.
//!
//! The host offers the image ([`Request::OtaOffer`]) and streams its
//! bytes on demand: the hub keeps a [`OTA_WINDOW`]-octet window ahead of
//! the downloading device and asks for more ([`Event::OtaDataWanted`])
//! whenever half of it is free. A block outside the window is answered
//! WAIT_FOR_DATA and asked for. One device downloads at a time; the
//! others are told there is no image until it is done.
//!
//! The image is offered only to devices whose manufacturer code and
//! image type match it and that run another version — an older one
//! unless the offer allows a downgrade — and to the target device only
//! when the offer names one. A device that verified the image is told to
//! upgrade now.

use heapless::Vec;
use panweave_aps::Destination;
use panweave_codec::{CodecError, Writer};
use panweave_runtime::{Stack, ZclFrame};
use panweave_security::cipher::BlockCipher;
use panweave_storage::Storage;
use panweave_types::time::{Duration, Instant};
use panweave_types::{CommandId, CryptoRng, Endpoint, ProfileId, ShortAddress};
use panweave_zcl::clusters::ota;
use panweave_zcl::{Direction, FrameType, Role, ZclStatus};

use crate::diag::{Category, DiagRecord, Severity, code};
use crate::hub::Hub;
use crate::protocol::{ErrorCode, Event, OtaOffer, OtaStatus, Request, Response};

/// Image octets the hub holds.
pub(crate) const OTA_WINDOW: usize = 1024;

/// Largest block sent (the APS payload of an Image Block Response).
const MAX_BLOCK: u8 = 64;

/// A device that stops asking for this long has given up.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// A request for data the host has not answered is repeated after this.
const WANTED_RETRY: Duration = Duration::from_secs(5);

/// Seconds a device waits after WAIT_FOR_DATA.
const WAIT_S: u32 = 1;

/// ABORT and TIMEOUT (ZCL8 Table 2-12).
const ABORT: u8 = 0x95;
const TIMEOUT: u8 = 0x94;

/// The OTA server state.
#[derive(Debug, Default)]
pub(crate) struct OtaServer {
    offer: Option<OtaOffer>,
    /// Image octets from `window_offset`.
    window: Vec<u8, OTA_WINDOW>,
    window_offset: u32,
    /// Offset asked of the host, and when.
    wanted: Option<(u32, Instant)>,
    /// The device downloading, the next offset it asked for, and when it
    /// was last heard.
    device: Option<(u64, u32, Instant)>,
    /// Last progress reported, in 5 % steps.
    progress: u8,
}

impl OtaServer {
    fn window_end(&self) -> u32 {
        self.window_offset
            .saturating_add(u32::try_from(self.window.len()).unwrap_or(u32::MAX))
    }

    /// Whether the device is downloading (and so is worth fast polling).
    pub(crate) fn serving(&self, ieee: u64) -> bool {
        self.offer.is_some() && self.device.is_some_and(|(d, ..)| d == ieee)
    }
}

/// Answers `origin` with cluster-specific command `cmd` and the payload
/// `encode` writes.
fn respond<C: BlockCipher, R: CryptoRng, S: Storage>(
    stack: &mut Stack<C, R, S>,
    origin: &panweave_zcl::layer::Origin,
    cmd: CommandId,
    encode: impl FnOnce(&mut Writer<'_>) -> Result<(), CodecError>,
) {
    let mut out = [0u8; 96];
    let mut w = Writer::new(&mut out);
    if encode(&mut w).is_ok() {
        let n = w.position();
        let _ = stack.zcl.respond(
            origin,
            cmd,
            FrameType::ClusterSpecific,
            out.get(..n).unwrap_or_default(),
        );
    }
}

impl<HS: Storage> Hub<HS> {
    /// OTA requests.
    pub(crate) fn handle_ota<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        request: &Request,
    ) -> Option<Result<Response, ErrorCode>> {
        Some(match request {
            Request::OtaOffer(offer) => self.ota_offer(stack, *offer).map(|()| Response::Done),
            Request::OtaData { offset, data } => {
                self.ota_data(*offset, data).map(|()| Response::Done)
            }
            Request::OtaCancel => {
                self.ota_cancel();
                Ok(Response::Done)
            }
            Request::GetOtaStatus => Ok(Response::OtaStatus(self.ota_status())),
            _ => return None,
        })
    }

    fn ota_status(&self) -> OtaStatus {
        let o = &self.ota;
        OtaStatus {
            offer: o.offer,
            device: o.device.map(|(d, ..)| d),
            offset: o.device.map_or(0, |(_, off, _)| off),
            window_offset: o.window_offset,
            window_len: u16::try_from(o.window.len()).unwrap_or(u16::MAX),
        }
    }

    /// Whether the hub's endpoint has the OTA server cluster (it may not,
    /// with the small tables).
    fn ota_available<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &Stack<C, R, S>,
    ) -> bool {
        stack
            .zcl
            .endpoint(self.config.endpoint)
            .is_some_and(|e| e.cluster(ota::ID, Role::Server).is_some())
    }

    fn ota_offer<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        offer: OtaOffer,
    ) -> Result<(), ErrorCode> {
        if !self.ota_available(stack) {
            return Err(ErrorCode::NotSupported);
        }
        // The file header alone is 56 octets (§11.4.2).
        if offer.image.size < u32::from(ota::MIN_HEADER_LEN) {
            return Err(ErrorCode::InvalidArgument);
        }
        if let Some((ieee, ..)) = self.ota.device {
            self.emit(Event::OtaFinished {
                ieee,
                status: ABORT,
            });
        }
        self.ota = OtaServer {
            offer: Some(offer),
            ..OtaServer::default()
        };
        self.ota_refill();
        self.log(
            DiagRecord::new(Category::Zcl, Severity::Info, code::OTA_OFFERED)
                .cluster(ota::ID.0)
                .arg(offer.image.file_version),
        );
        // Tell the target to ask now rather than at its next periodic
        // query (Image Notify, payload type 0, §11.13.3).
        if let Some(target) = offer.target
            && let Some(d) = self.registry.get(target)
            && d.present
        {
            let ep = d
                .endpoints
                .iter()
                .find(|e| e.outputs.contains(&ota::ID.0))
                .map_or(1, |e| e.endpoint);
            let mut buf = [0u8; 8];
            let mut w = Writer::new(&mut buf);
            let notify = ota::ImageNotify {
                query_jitter: 100,
                manufacturer_code: None,
                image_type: None,
                file_version: None,
            };
            if notify.encode(&mut w).is_ok() {
                let n = w.position();
                let _ = stack.zcl.send_command(
                    Destination::Short {
                        address: ShortAddress(d.short),
                        endpoint: Endpoint(ep),
                    },
                    ProfileId::HOME_AUTOMATION,
                    ota::ID,
                    self.config.endpoint,
                    ota::CMD_IMAGE_NOTIFY,
                    Direction::ToClient,
                    None,
                    buf.get(..n).unwrap_or_default(),
                );
                stack.flush();
            }
        }
        Ok(())
    }

    fn ota_data(&mut self, offset: u32, data: &[u8]) -> Result<(), ErrorCode> {
        let o = &mut self.ota;
        let Some(offer) = o.offer else {
            return Err(ErrorCode::InvalidArgument);
        };
        let end = o.window_end();
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        if offset > end || offset.saturating_add(len) > offer.image.size {
            return Err(ErrorCode::InvalidArgument);
        }
        // Octets the window already has (a repeated answer) are skipped.
        let skip = usize::try_from(end - offset).unwrap_or(usize::MAX);
        let fresh = data.get(skip..).unwrap_or_default();
        if o.window.len() + fresh.len() > OTA_WINDOW {
            return Err(ErrorCode::InvalidArgument);
        }
        let _ = o.window.extend_from_slice(fresh);
        if o.wanted.is_some_and(|(w, _)| w < o.window_end()) {
            o.wanted = None;
        }
        self.ota_refill();
        Ok(())
    }

    fn ota_cancel(&mut self) {
        if let Some((ieee, ..)) = self.ota.device {
            self.emit(Event::OtaFinished {
                ieee,
                status: ABORT,
            });
        }
        self.ota = OtaServer::default();
    }

    /// Asks the host for more octets when half of the window is free.
    fn ota_refill(&mut self) {
        let now = self.now;
        let o = &mut self.ota;
        let Some(offer) = o.offer else {
            return;
        };
        let end = o.window_end();
        let free = OTA_WINDOW - o.window.len();
        if end >= offer.image.size || free < OTA_WINDOW / 2 {
            return;
        }
        if o.wanted
            .is_some_and(|(w, t)| w == end && now.saturating_duration_since(t) < WANTED_RETRY)
        {
            return;
        }
        o.wanted = Some((end, now));
        let length = u32::try_from(free)
            .unwrap_or(u32::MAX)
            .min(offer.image.size - end);
        self.emit(Event::OtaDataWanted {
            offset: end,
            length: u16::try_from(length).unwrap_or(u16::MAX),
        });
    }

    /// Moves the window to `offset` (a device asked for octets outside
    /// it).
    fn ota_seek(&mut self, offset: u32) {
        let o = &mut self.ota;
        o.window.clear();
        o.window_offset = offset;
        o.wanted = None;
        self.ota_refill();
    }

    /// Releases a device that stopped downloading; asks again for data
    /// the host did not send. Called from the hub's poll.
    pub(crate) fn poll_ota(&mut self) {
        let now = self.now;
        if let Some((ieee, _, at)) = self.ota.device
            && now.saturating_duration_since(at).as_millis() >= TRANSFER_TIMEOUT.as_millis()
        {
            self.ota.device = None;
            self.emit(Event::OtaFinished {
                ieee,
                status: TIMEOUT,
            });
        }
        self.ota_refill();
    }

    /// The next instant [`Hub::poll`] has OTA work.
    pub(crate) fn ota_deadline(&self) -> Option<Instant> {
        let mut next = self.ota.device.map(|(.., at)| at + TRANSFER_TIMEOUT);
        if let Some((_, t)) = self.ota.wanted {
            let retry = t + WANTED_RETRY;
            if next.is_none_or(|n| retry.as_millis() < n.as_millis()) {
                next = Some(retry);
            }
        }
        next
    }

    /// Whether the offer suits the device asking.
    fn ota_suits(&self, ieee: u64, req: &ota::QueryNextImageRequest) -> Option<OtaOffer> {
        let offer = self.ota.offer?;
        let i = offer.image;
        let version_ok = if offer.allow_downgrade {
            req.file_version != i.file_version
        } else {
            req.file_version < i.file_version
        };
        let target_ok = offer.target.is_none_or(|t| t == ieee);
        let free = self.ota.device.is_none_or(|(d, ..)| d == ieee);
        (req.manufacturer_code == i.manufacturer_code
            && req.image_type == i.image_type
            && version_ok
            && target_ok
            && free)
            .then_some(offer)
    }

    /// An OTA client command to the hub's server (§11.13.4–§11.13.9).
    pub(crate) fn on_ota_command<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        i: Option<usize>,
        f: &ZclFrame,
    ) {
        let origin = &f.origin;
        let ieee = i.and_then(|i| self.registry.at(i)).map(|d| d.ieee);
        let now = self.now;
        match origin.header.command {
            ota::CMD_QUERY_NEXT_IMAGE_REQUEST => {
                let Ok(req) = ota::QueryNextImageRequest::parse(&f.payload) else {
                    let _ = stack
                        .zcl
                        .default_response(origin, ZclStatus::MalformedCommand);
                    return;
                };
                let offer = ieee.and_then(|d| self.ota_suits(d, &req));
                let rsp = match offer {
                    Some(o) => ota::QueryNextImageResponse {
                        status: ZclStatus::Success,
                        image: Some(ota::ImageId {
                            manufacturer_code: o.image.manufacturer_code,
                            image_type: o.image.image_type,
                            file_version: o.image.file_version,
                        }),
                        image_size: o.image.size,
                    },
                    None => ota::QueryNextImageResponse {
                        status: ZclStatus::NoImageAvailable,
                        image: None,
                        image_size: 0,
                    },
                };
                if let (Some(_), Some(d)) = (offer, ieee) {
                    self.ota.device = Some((d, 0, now));
                    self.ota.progress = 0;
                }
                respond(stack, origin, ota::CMD_QUERY_NEXT_IMAGE_RESPONSE, |w| {
                    rsp.encode(w)
                });
            }
            ota::CMD_IMAGE_BLOCK_REQUEST => {
                let Ok(req) = ota::ImageBlockRequest::parse(&f.payload) else {
                    let _ = stack
                        .zcl
                        .default_response(origin, ZclStatus::MalformedCommand);
                    return;
                };
                let mut data = [0u8; MAX_BLOCK as usize];
                let rsp = self.ota_block(ieee, &req, &mut data);
                respond(stack, origin, ota::CMD_IMAGE_BLOCK_RESPONSE, |w| {
                    rsp.encode(w)
                });
            }
            ota::CMD_UPGRADE_END_REQUEST => {
                let Ok(req) = ota::UpgradeEndRequest::parse(&f.payload) else {
                    let _ = stack
                        .zcl
                        .default_response(origin, ZclStatus::MalformedCommand);
                    return;
                };
                let ours = ieee.is_some_and(|d| self.ota.serving(d));
                if ours && req.status == ZclStatus::Success {
                    // Upgrade now (§11.13.9.4: current and upgrade time 0).
                    let rsp = ota::UpgradeEndResponse {
                        image: req.image,
                        current_time: 0,
                        upgrade_time: 0,
                    };
                    respond(stack, origin, ota::CMD_UPGRADE_END_RESPONSE, |w| {
                        rsp.encode(w)
                    });
                } else {
                    let _ = stack.zcl.default_response(origin, ZclStatus::Success);
                }
                if ours && let Some(d) = ieee {
                    self.ota.device = None;
                    let status = req.status.raw();
                    self.log(
                        DiagRecord::new(Category::Zcl, Severity::Info, code::OTA_FINISHED)
                            .ieee(d)
                            .cluster(ota::ID.0)
                            .status(status),
                    );
                    self.emit(Event::OtaFinished { ieee: d, status });
                    // A targeted offer is done with its device.
                    if self.ota.offer.is_some_and(|o| o.target == Some(d)) {
                        self.ota = OtaServer::default();
                    }
                }
            }
            _ => {
                // Image Page Request and device-specific files are not
                // served: the client falls back to block requests.
                let _ = stack
                    .zcl
                    .default_response(origin, ZclStatus::UnsupportedClusterCommand);
            }
        }
        stack.flush();
    }

    /// The answer to an Image Block Request.
    fn ota_block<'a>(
        &mut self,
        ieee: Option<u64>,
        req: &ota::ImageBlockRequest,
        buf: &'a mut [u8],
    ) -> ota::ImageBlockResponse<'a> {
        let now = self.now;
        let Some(offer) = self.ota.offer else {
            return ota::ImageBlockResponse::Abort;
        };
        let i = offer.image;
        let same_image = req.image.manufacturer_code == i.manufacturer_code
            && req.image.image_type == i.image_type
            && req.image.file_version == i.file_version;
        let Some(d) = ieee.filter(|d| same_image && self.ota.serving(*d)) else {
            return ota::ImageBlockResponse::Abort;
        };
        if req.file_offset >= i.size {
            return ota::ImageBlockResponse::Abort;
        }
        self.ota.device = Some((d, req.file_offset, now));
        let o = &self.ota;
        if req.file_offset < o.window_offset || req.file_offset >= o.window_end() {
            // Not held: fetch it and have the device come back.
            if !(req.file_offset == o.window_end() && o.wanted.is_some()) {
                self.ota_seek(req.file_offset);
            } else {
                self.ota_refill();
            }
            return ota::ImageBlockResponse::WaitForData {
                current_time: 0,
                request_time: WAIT_S,
                minimum_block_period: 0,
            };
        }
        let from = usize::try_from(req.file_offset - o.window_offset).unwrap_or(usize::MAX);
        let want = usize::from(req.max_data_size.min(MAX_BLOCK)).min(buf.len());
        let available = o.window.get(from..).unwrap_or_default();
        let n = want.min(available.len());
        let (block, _) = buf.split_at_mut(n);
        block.copy_from_slice(available.get(..n).unwrap_or_default());
        let next = req.file_offset + u32::try_from(n).unwrap_or(0);
        // Drop what the device has, once that is half the window, and
        // ask for more.
        if from >= OTA_WINDOW / 2 {
            let o = &mut self.ota;
            let keep: Vec<u8, OTA_WINDOW> =
                Vec::from_slice(o.window.get(from..).unwrap_or_default()).unwrap_or_default();
            o.window = keep;
            o.window_offset = req.file_offset;
        }
        self.ota_refill();
        let pct = u8::try_from(u64::from(next) * 20 / u64::from(i.size.max(1))).unwrap_or(20);
        if pct > self.ota.progress {
            self.ota.progress = pct;
            self.emit(Event::OtaProgress {
                ieee: d,
                offset: next,
                size: i.size,
            });
        }
        ota::ImageBlockResponse::Success {
            image: req.image,
            file_offset: req.file_offset,
            data: block,
        }
    }
}
