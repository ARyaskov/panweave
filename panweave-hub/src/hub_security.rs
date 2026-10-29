//! The hub's side of the Trust Center authorization policy
//! (`panweave_runtime::authorization`): devices without application
//! access are neither registered nor interviewed, administrator
//! exemptions from the key exchange are bounded in time until the device
//! joins and then persisted with it, and the security state is reported
//! to the host.

use heapless::Vec;
use panweave_runtime::{Authorization, Stack};
use panweave_security::cipher::BlockCipher;
use panweave_security::key_hierarchy::link_key_from_install_code;
use panweave_security::material::{InitialJoinAuthentication, LinkKeyEntry, LinkKeyKind};
use panweave_storage::Storage;
use panweave_types::time::Duration;
use panweave_types::{CryptoRng, ExtendedAddress, InstallCode, ShortAddress};

use crate::diag::{Category, DiagRecord, Severity, code};
use crate::hub::Hub;
use crate::protocol::{
    DeniedCounts, DeviceAuthorization, ErrorCode, ExemptionInfo, MAX_EXEMPTION_SECONDS, Request,
    Response, SecurityStatus,
};

/// The protocol form of the stack's verdict.
pub(crate) const fn wire(a: Authorization) -> DeviceAuthorization {
    match a {
        Authorization::Authorized => DeviceAuthorization::Authorized,
        Authorization::Exempt => DeviceAuthorization::Exempt,
        Authorization::PendingKeyExchange => DeviceAuthorization::PendingKeyExchange,
        Authorization::KeyExchangeIncomplete => DeviceAuthorization::KeyExchangeIncomplete,
        Authorization::Unknown => DeviceAuthorization::Unknown,
    }
}

impl<HS: Storage> Hub<HS> {
    /// Whether the hub may register, interview and serve `ieee`.
    pub(crate) fn may_serve<C: BlockCipher, R: CryptoRng, S: Storage>(
        stack: &Stack<C, R, S>,
        ieee: u64,
    ) -> bool {
        stack
            .device_authorization(ExtendedAddress(ieee))
            .grants_application_access()
    }

    /// Records that `ieee` was turned away for lack of authorization.
    pub(crate) fn log_not_authorized<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &Stack<C, R, S>,
        ieee: u64,
        short: Option<u16>,
    ) {
        let a = wire(stack.device_authorization(ExtendedAddress(ieee)));
        let severity = if a == DeviceAuthorization::PendingKeyExchange {
            Severity::Debug
        } else {
            Severity::Warning
        };
        let mut rec = DiagRecord::new(Category::TrustCenter, severity, code::DEVICE_NOT_AUTHORIZED)
            .ieee(ieee)
            .status(a.code());
        if let Some(s) = short {
            rec = rec.short(s);
        }
        self.log(rec);
    }

    /// Applies the persisted exemptions to the stack (once after start-up
    /// or a factory reset), reports registered devices without
    /// application access, and expires exemption windows.
    pub(crate) fn poll_security<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
    ) {
        if !self.exemptions_applied {
            self.exemptions_applied = true;
            stack.clear_key_exchange_exemptions();
            let mut wanted: Vec<u64, { crate::protocol::MAX_EXEMPTIONS }> = Vec::new();
            for d in self.registry.iter().filter(|d| d.key_exchange_exempt) {
                let _ = wanted.push(d.ieee);
            }
            // Commissioning grants (RAM only) are re-applied with what is
            // left of their window; admitted exemptions as admitted.
            let grants = self.exemption_grants.clone();
            for (ieee, until) in grants {
                let left = until.saturating_duration_since(self.now);
                if left.as_millis() > 0 {
                    let _ = stack.grant_commissioning_exemption(ExtendedAddress(ieee), left);
                }
            }
            // The registry's addresses seed the stack's address map, so
            // the application frames of known devices can be attributed
            // after a restart without a resolution round trip. The
            // registry is the hub's own storage; a device that moved is
            // corrected by the frames it sends.
            for d in self.registry.iter() {
                if d.short != crate::registry::NO_SHORT
                    && stack
                        .nwk
                        .address_map
                        .short_for(ExtendedAddress(d.ieee))
                        .is_none()
                {
                    let _ = stack
                        .nwk
                        .address_map
                        .record(ExtendedAddress(d.ieee), ShortAddress(d.short));
                }
            }
            for ieee in wanted {
                if stack
                    .set_key_exchange_exemption(ExtendedAddress(ieee), true)
                    .is_err()
                {
                    self.log(
                        DiagRecord::new(
                            Category::TrustCenter,
                            Severity::Error,
                            code::KEY_EXCHANGE_EXEMPTION_REVOKED,
                        )
                        .ieee(ieee)
                        .status(1),
                    );
                }
            }
            let mut unserved: Vec<u64, { crate::protocol::MAX_UNAUTHORIZED }> = Vec::new();
            for d in self.registry.iter() {
                if !Self::may_serve(stack, d.ieee) {
                    let _ = unserved.push(d.ieee);
                }
            }
            for ieee in unserved {
                self.log_not_authorized(stack, ieee, None);
            }
        }
        // A grant ends when the stack's commissioning exemption is gone:
        // consumed by a join (handled in `after_authorized`) or expired.
        while let Some(i) = self.exemption_grants.iter().position(|(d, _)| {
            stack.commissioning_exemption(ExtendedAddress(*d)).is_none()
                && !stack.key_exchange_exempt(ExtendedAddress(*d))
        }) {
            let (ieee, _) = self.exemption_grants.swap_remove(i);
            self.log(
                DiagRecord::new(
                    Category::TrustCenter,
                    Severity::Info,
                    code::KEY_EXCHANGE_EXEMPTION_EXPIRED,
                )
                .ieee(ieee),
            );
        }
    }

    /// A device was authorized and registered: an exemption granted for
    /// it is kept with it when it was what authorized the device, and
    /// dropped when the device completed the key exchange anyway.
    pub(crate) fn after_authorized<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        ieee: u64,
    ) {
        let Some(i) = self.exemption_grants.iter().position(|(d, _)| *d == ieee) else {
            return;
        };
        let _ = self.exemption_grants.swap_remove(i);
        if stack.device_authorization(ExtendedAddress(ieee)) == Authorization::Exempt {
            if let Some(d) = self.registry.get_mut(ieee) {
                d.key_exchange_exempt = true;
                d.dirty = true;
            }
            self.schedule_persist();
            self.log(
                DiagRecord::new(
                    Category::TrustCenter,
                    Severity::Warning,
                    code::KEY_EXCHANGE_EXEMPTION_USED,
                )
                .ieee(ieee),
            );
        } else {
            let _ = stack.set_key_exchange_exemption(ExtendedAddress(ieee), false);
        }
    }

    /// A device's window opened: an admitted exemption the stack withdrew
    /// (the device joined again through the unauthenticated path) is
    /// withdrawn from the registry too.
    pub(crate) fn on_key_exchange_pending<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &Stack<C, R, S>,
        ieee: u64,
    ) {
        let withdrawn = !stack.key_exchange_exempt(ExtendedAddress(ieee));
        if let Some(d) = self.registry.get_mut(ieee)
            && d.key_exchange_exempt
            && withdrawn
        {
            d.key_exchange_exempt = false;
            d.dirty = true;
            self.schedule_persist();
            self.log(
                DiagRecord::new(
                    Category::TrustCenter,
                    Severity::Warning,
                    code::KEY_EXCHANGE_EXEMPTION_REVOKED,
                )
                .ieee(ieee)
                .status(2),
            );
        }
    }

    /// Forgets a device's exemption (the device was removed).
    pub(crate) fn drop_exemption<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        ieee: u64,
    ) {
        self.exemption_grants.retain(|(d, _)| *d != ieee);
        let _ = stack.set_key_exchange_exemption(ExtendedAddress(ieee), false);
    }

    fn security_status<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &Stack<C, R, S>,
    ) -> SecurityStatus {
        let policy = &stack.config.trust_center_policy;
        let mut s = SecurityStatus {
            require_key_exchange: policy.require_key_exchange,
            node_join_timeout_s: policy.node_join_timeout_s,
            pending_key_exchanges: u8::try_from(stack.pending_key_exchanges()).unwrap_or(u8::MAX),
            key_exchange_timeouts: stack.key_exchange_timeouts(),
            unauthorized_frames_dropped: stack.unauthorized_frames_dropped(),
            denied: {
                let d = stack.denied_frames();
                DeniedCounts {
                    unresolved: d.unresolved,
                    inconsistent: d.inconsistent,
                    unknown: d.unknown,
                    pending: d.pending,
                    incomplete: d.incomplete,
                }
            },
            exemptions_used: stack.commissioning_exemptions().0,
            exemptions_expired: stack.commissioning_exemptions().1,
            link_keys: u8::try_from(stack.aps.security.keys().len()).unwrap_or(u8::MAX),
            link_key_capacity: u8::try_from(panweave_runtime::LINK_KEYS).unwrap_or(u8::MAX),
            ..SecurityStatus::default()
        };
        for (ieee, _) in &self.exemption_grants {
            let Some(until) = stack.commissioning_exemption(ExtendedAddress(*ieee)) else {
                continue;
            };
            let left = until.saturating_duration_since(self.now).as_secs();
            let _ = s.exemptions.push(ExemptionInfo {
                ieee: *ieee,
                remaining_s: Some(u16::try_from(left).unwrap_or(u16::MAX)),
            });
        }
        for d in self.registry.iter() {
            if d.key_exchange_exempt {
                let _ = s.exemptions.push(ExemptionInfo {
                    ieee: d.ieee,
                    remaining_s: None,
                });
            }
            let a = stack.device_authorization(ExtendedAddress(d.ieee));
            if !a.grants_application_access() {
                let _ = s.unauthorized.push((d.ieee, wire(a)));
            }
        }
        s
    }

    /// Answers the security requests; `None` for any other request.
    pub(crate) fn handle_security<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        request: &Request,
    ) -> Option<Result<Response, ErrorCode>> {
        Some(match request {
            Request::GetSecurityStatus => Ok(Response::SecurityStatus(self.security_status(stack))),
            Request::SetKeyExchangeExemption { ieee, seconds } => self
                .set_exemption(stack, *ieee, *seconds)
                .map(|()| Response::Done),
            Request::AddInstallCode { ieee, code } => self
                .add_install_code(stack, *ieee, code)
                .map(|()| Response::Done),
            _ => return None,
        })
    }

    /// Installs the link key derived from `ieee`'s install code at the
    /// Trust Center (BDB §10.1, R23.2 §4.7.3.3): a provisional unique key
    /// the device joins with and then updates.
    fn add_install_code<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        ieee: u64,
        code: &[u8],
    ) -> Result<(), ErrorCode> {
        if ieee == 0 || ieee == u64::MAX {
            return Err(ErrorCode::InvalidArgument);
        }
        let ic = InstallCode::new(code).ok_or(ErrorCode::InvalidArgument)?;
        if !ic.crc_valid() {
            return Err(ErrorCode::InvalidArgument);
        }
        let key = link_key_from_install_code::<C>(&ic);
        let partner = ExtendedAddress(ieee);
        stack.aps.security.remove(partner);
        let mut entry = LinkKeyEntry::provisional(partner, key, LinkKeyKind::Unique);
        entry.initial_join_authentication = InitialJoinAuthentication::InstallCodeKey;
        stack
            .aps
            .install_link_key(entry)
            .map_err(|_| ErrorCode::RegistryFull)?;
        stack.flush();
        self.log(
            DiagRecord::new(
                Category::TrustCenter,
                Severity::Info,
                code::INSTALL_CODE_ADDED,
            )
            .ieee(ieee)
            .arg(u32::try_from(ic.as_bytes().len()).unwrap_or(0)),
        );
        Ok(())
    }

    fn set_exemption<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        ieee: u64,
        seconds: u16,
    ) -> Result<(), ErrorCode> {
        if ieee == 0 || ieee == u64::MAX || seconds > MAX_EXEMPTION_SECONDS {
            return Err(ErrorCode::InvalidArgument);
        }
        if seconds == 0 {
            self.exemption_grants.retain(|(d, _)| *d != ieee);
            let _ = stack.set_key_exchange_exemption(ExtendedAddress(ieee), false);
            if let Some(d) = self.registry.get_mut(ieee)
                && d.key_exchange_exempt
            {
                d.key_exchange_exempt = false;
                d.dirty = true;
                self.schedule_persist();
            }
            self.log(
                DiagRecord::new(
                    Category::TrustCenter,
                    Severity::Warning,
                    code::KEY_EXCHANGE_EXEMPTION_REVOKED,
                )
                .ieee(ieee),
            );
            return Ok(());
        }
        let registered = self.registry.get(ieee).is_some();
        if !registered
            && !self.exemption_grants.iter().any(|(d, _)| *d == ieee)
            && self.exemption_grants.is_full()
        {
            return Err(ErrorCode::Busy);
        }
        if registered {
            stack
                .set_key_exchange_exemption(ExtendedAddress(ieee), true)
                .map_err(|_| ErrorCode::Busy)?;
        } else {
            stack
                .grant_commissioning_exemption(
                    ExtendedAddress(ieee),
                    Duration::from_secs(u64::from(seconds)),
                )
                .map_err(|_| ErrorCode::Busy)?;
        }
        if registered {
            // A device already in the registry (for example one paired by
            // an older firmware that never exchanged its key): permanent.
            if let Some(d) = self.registry.get_mut(ieee) {
                d.key_exchange_exempt = true;
                d.dirty = true;
            }
            self.schedule_persist();
        } else {
            let until = self
                .now
                .saturating_add(Duration::from_secs(u64::from(seconds)));
            self.exemption_grants.retain(|(d, _)| *d != ieee);
            let _ = self.exemption_grants.push((ieee, until));
        }
        self.log(
            DiagRecord::new(
                Category::TrustCenter,
                Severity::Warning,
                code::KEY_EXCHANGE_EXEMPTION_GRANTED,
            )
            .ieee(ieee)
            .status(u8::from(registered))
            .arg(u32::from(seconds)),
        );
        Ok(())
    }
}
