//! The hub as Green Power Combo Basic sink (feature `green-power`): the
//! stack's sink (`panweave_runtime::green_power`) commissions and pairs
//! GPDs and filters their frames; the hub opens the commissioning window
//! for the host and turns the sink's events into protocol events.

use heapless::Vec;
use panweave_green_power::gpdf::GpdId;
use panweave_runtime::green_power::SinkOptions;
use panweave_runtime::{Stack, StackEvent};
use panweave_security::cipher::BlockCipher;
use panweave_storage::Storage;
use panweave_types::time::Duration;
use panweave_types::{CryptoRng, ExtendedAddress};

use crate::diag::{Category, DiagRecord, Severity, code};
use crate::hub::Hub;
use crate::protocol::{
    ErrorCode, Event, GPD_PAGE, GpdAddress, GpdInfo, GpdList, Request, Response,
};

/// The protocol form of a GPD identity.
pub(crate) const fn address(gpd: GpdId) -> GpdAddress {
    match gpd {
        GpdId::SrcId(id) => GpdAddress::SrcId(id),
        GpdId::Ieee { address, endpoint } => GpdAddress::Ieee {
            ieee: address.0,
            endpoint,
        },
    }
}

const fn gpd_id(a: GpdAddress) -> GpdId {
    match a {
        GpdAddress::SrcId(id) => GpdId::SrcId(id),
        GpdAddress::Ieee { ieee, endpoint } => GpdId::Ieee {
            address: ExtendedAddress(ieee),
            endpoint,
        },
    }
}

impl<HS: Storage> Hub<HS> {
    /// Enables the stack's Green Power Combo Basic sink (endpoint 242).
    pub(crate) fn attach_green_power<C: BlockCipher, R: CryptoRng, S: Storage>(
        stack: &mut Stack<C, R, S>,
    ) {
        let _ = stack.enable_green_power_sink(SinkOptions::default());
    }

    /// Green Power requests.
    pub(crate) fn handle_green_power<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        request: &Request,
    ) -> Option<Result<Response, ErrorCode>> {
        Some(match request {
            Request::GreenPowerCommission { seconds } => {
                if stack.green_power_sink_ref().is_none() {
                    Err(ErrorCode::NotSupported)
                } else if *seconds == 0 {
                    stack.green_power_stop_commissioning();
                    stack.flush();
                    Ok(Response::Done)
                } else {
                    let window = Duration::from_secs(u64::from(*seconds));
                    let r = stack
                        .green_power_commission(true, Some(window))
                        .map(|_| Response::Done)
                        .map_err(|_| ErrorCode::Busy);
                    stack.flush();
                    r
                }
            }
            Request::ListGreenPowerDevices { start } => match stack.green_power_sink_ref() {
                None => Err(ErrorCode::NotSupported),
                Some(sink) => {
                    let mut devices = Vec::new();
                    for e in sink.table.iter().skip(usize::from(*start)).take(GPD_PAGE) {
                        let _ = devices.push(GpdInfo {
                            gpd: address(e.gpd),
                            device_id: e.device_id,
                        });
                    }
                    Ok(Response::GreenPowerDevices(GpdList {
                        total: u8::try_from(sink.table.len()).unwrap_or(u8::MAX),
                        start: *start,
                        devices,
                    }))
                }
            },
            Request::RemoveGreenPowerDevice { gpd } => {
                let id = gpd_id(*gpd);
                let removed = stack.green_power_sink().map(|sink| sink.table.remove(&id));
                match removed {
                    None => Err(ErrorCode::NotSupported),
                    Some(0) => Err(ErrorCode::UnknownDevice),
                    Some(_) => {
                        let _ = stack.persist_sink_table();
                        stack.flush();
                        self.emit(Event::GreenPowerRemoved { gpd: *gpd });
                        Ok(Response::Done)
                    }
                }
            }
            _ => return None,
        })
    }

    /// The sink's events.
    pub(crate) fn on_green_power_event(&mut self, event: &StackEvent) {
        match event {
            StackEvent::GreenPowerCommissioningMode { until } => {
                let seconds = until.map_or(0, |t| {
                    let ms = self.now.saturating_duration_until(t).as_millis();
                    u16::try_from(ms.div_ceil(1000)).unwrap_or(u16::MAX).max(1)
                });
                self.emit(Event::GreenPowerCommissioning { seconds });
            }
            StackEvent::GreenPowerPaired { gpd, device_id, .. } => {
                self.log(
                    DiagRecord::new(Category::Commissioning, Severity::Info, code::GPD_PAIRED)
                        .status(*device_id)
                        .arg(match gpd {
                            GpdId::SrcId(id) => *id,
                            GpdId::Ieee { address, .. } => {
                                u32::try_from(address.0 & 0xffff_ffff).unwrap_or(0)
                            }
                        }),
                );
                self.emit(Event::GreenPowerPaired {
                    gpd: address(*gpd),
                    device_id: *device_id,
                });
            }
            StackEvent::GreenPowerDecommissioned { gpd } => {
                self.emit(Event::GreenPowerRemoved { gpd: address(*gpd) });
            }
            StackEvent::GreenPowerRefused { gpd, reason } => {
                let _ = reason;
                self.log(
                    DiagRecord::new(
                        Category::Commissioning,
                        Severity::Warning,
                        code::GPD_REFUSED,
                    )
                    .arg(match gpd {
                        GpdId::SrcId(id) => *id,
                        GpdId::Ieee { address, .. } => {
                            u32::try_from(address.0 & 0xffff_ffff).unwrap_or(0)
                        }
                    }),
                );
            }
            StackEvent::GreenPowerCommand {
                gpd,
                command_id,
                payload,
                ..
            } => {
                let payload = Vec::from_slice(
                    payload
                        .get(..payload.len().min(crate::protocol::MAX_GPD_PAYLOAD))
                        .unwrap_or_default(),
                )
                .unwrap_or_default();
                self.emit(Event::GreenPowerCommand {
                    gpd: address(*gpd),
                    command: *command_id,
                    payload,
                });
            }
            _ => {}
        }
    }
}
