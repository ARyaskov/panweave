//! Dynamic Link Key negotiation (R23.2 §4.4.9, §4.6.3.5, §4.7.3.3):
//! the initiator side of the SPEKE exchange over the ZDO security
//! services, the Trust Center's bookkeeping of joiners negotiating a key
//! before receiving the network key, and the shared state the ZDO
//! context uses to answer Security_Start_Key_Negotiation_req.
//!
//! The cryptography lives in `panweave_security::dlk`; this module owns
//! the protocol state: which entry is being replaced, the ephemeral
//! scalar awaiting the peer's public point, the backup of the previous
//! key-pair entry restored on failure (§4.4.9), and the
//! `apsSecurityTimeOutPeriod` deadlines.
//!
//! Without the `dlk` feature the negotiation itself is compiled out:
//! requests are answered with NOT_SUPPORTED and the Trust Center never
//! selects key negotiation.
#![cfg_attr(
    not(feature = "dlk"),
    allow(dead_code, clippy::unused_self, clippy::needless_return)
)]

use heapless::Vec;
#[cfg(feature = "dlk")]
use panweave_aps::layer::NwkView;
use panweave_aps::layer::{KeyRoute, RelayInfo};
use panweave_security::cipher::BlockCipher;
#[cfg(feature = "dlk")]
use panweave_security::dlk::Ephemeral;
#[cfg(feature = "dlk")]
use panweave_security::material::InitialJoinAuthentication;
#[cfg(feature = "dlk")]
use panweave_security::material::{KeyNegotiationState, LinkKeyKind};
use panweave_security::material::{LinkKeyEntry, PostJoinKeyUpdate};
use panweave_storage::Storage;
use panweave_types::time::Instant;
use panweave_types::{CryptoRng, ExtendedAddress, Key128, ShortAddress};
#[cfg(feature = "dlk")]
use panweave_types::{KeyAttributes, KeyType};
use panweave_zdo::ZdpStatus;
#[cfg(feature = "dlk")]
use panweave_zdo::cluster;
use panweave_zdo::security::SelectedKeyNegotiationMethod;
#[cfg(feature = "dlk")]
use panweave_zdo::security::{PublicPoint, StartKeyNegotiationReq};

#[cfg(feature = "dlk")]
use crate::stack::Phase;
use crate::stack::{Stack, StackEvent};

/// Concurrent joiners the Trust Center negotiates with.
pub const MAX_PENDING_JOINS: usize = 4;

/// `apscWellknownPSK` (Table 4-37): the anonymous pre-shared secret.
pub const WELL_KNOWN_PSK: &[u8; 16] = b"ZigBeeAlliance18";

/// Placeholder when Curve25519 is compiled out: no session is ever
/// created.
#[cfg(not(feature = "dlk"))]
pub(crate) struct Ephemeral;

/// Initiator-side negotiation in progress.
pub(crate) struct Session {
    /// The peer (the Trust Center for TCLK negotiation).
    pub partner: ExtendedAddress,
    /// Our ephemeral scalar / public point.
    pub ephemeral: Ephemeral,
    /// Selected protocol (Table 2-80).
    pub protocol: u8,
    /// Selected pre-shared secret (Table 2-81).
    pub secret: u8,
    /// Relay through the parent while joining.
    pub via: Option<RelayInfo>,
    /// The entry before negotiation, restored on failure.
    pub backup: Option<LinkKeyEntry>,
    /// Negotiation must complete before this.
    pub deadline: Instant,
    /// Waiting for the Confirm Key after Verify Key.
    pub verifying: bool,
}

/// A joiner the Trust Center asked to negotiate a key (§4.7.3.3).
#[derive(Clone, Copy, Debug)]
pub(crate) struct PendingJoin {
    pub device: ExtendedAddress,
    pub short: ShortAddress,
    /// The router that relays (None when the Trust Center is the parent).
    pub parent: Option<ShortAddress>,
    /// Selected pre-shared secret (Table 2-81).
    pub secret: u8,
    pub deadline: Instant,
}

/// DLK state of a stack.
#[derive(Default)]
pub(crate) struct DlkState {
    pub session: Option<Session>,
    pub joins: Vec<PendingJoin, MAX_PENDING_JOINS>,
    /// A Security_Start_Key_Update_req accepted by the ZDO: the runtime
    /// starts the negotiation after the response was queued.
    pub start_requested: Option<(SelectedKeyNegotiationMethod, Option<RelayInfo>)>,
}

/// The pre-shared secret for `secret` (Table 2-81) from `entry`.
pub(crate) fn passphrase_for(entry: Option<&LinkKeyEntry>, secret: u8) -> Option<Key128> {
    match secret {
        SelectedKeyNegotiationMethod::SECRET_ANONYMOUS => Some(Key128::from_bytes(*WELL_KNOWN_PSK)),
        SelectedKeyNegotiationMethod::SECRET_AUTH_TOKEN => entry?.passphrase.clone(),
        SelectedKeyNegotiationMethod::SECRET_INSTALL_CODE => {
            // The install-code derived key doubles as the passphrase
            // (§4.7.3.3 step "Passphrase = <Install Code derived key>").
            let e = entry?;
            e.passphrase.clone().or_else(|| Some(e.key.clone()))
        }
        _ => None,
    }
}

/// Post-join key update method for a negotiation with `secret`.
pub(crate) const fn update_method(secret: u8) -> PostJoinKeyUpdate {
    if secret == SelectedKeyNegotiationMethod::SECRET_ANONYMOUS {
        PostJoinKeyUpdate::UnauthenticatedNegotiation
    } else {
        PostJoinKeyUpdate::AuthenticatedNegotiation
    }
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Stack<C, R, S> {
    /// Starts a negotiation with `partner` using the selected method
    /// (APSME-KEY-NEGOTIATE.request, §4.4.9.1): backs the entry up, draws
    /// an ephemeral scalar and sends Security_Start_Key_Negotiation_req.
    pub(crate) fn start_key_negotiation(
        &mut self,
        partner: ExtendedAddress,
        method: SelectedKeyNegotiationMethod,
        via: Option<RelayInfo>,
    ) -> Result<(), ZdpStatus> {
        #[cfg(not(feature = "dlk"))]
        {
            let _ = (partner, method, via);
            return Err(ZdpStatus::NotSupported);
        }
        #[cfg(feature = "dlk")]
        {
            if self.dlk.session.is_some() {
                return Err(ZdpStatus::TemporaryFailure);
            }
            if method.protocol != SelectedKeyNegotiationMethod::PROTOCOL_SPEKE_AES_MMO {
                // SHA-256 SPEKE and CBKE are not implemented (conformance
                // PW-R23-ZDP-016).
                return Err(ZdpStatus::NoMatch);
            }
            let entry = self.aps.security.entry(partner);
            let psk = passphrase_for(entry, method.secret).ok_or(ZdpStatus::NoMatch)?;
            let backup = entry.cloned();
            let ephemeral = Ephemeral::generate::<C, _>(self.nwk.rng(), psk.as_bytes());
            let point = PublicPoint {
                device: self.config.ieee,
                point: *ephemeral.public(),
            };
            let mut tlvs = [0u8; PublicPoint::TLV_LEN];
            let mut w = panweave_codec::Writer::new(&mut tlvs);
            point
                .write(&mut w)
                .map_err(|_| ZdpStatus::TemporaryFailure)?;
            let req = StartKeyNegotiationReq { tlvs: &tlvs };
            let dst = crate::context::AddrView(&self.nwk)
                .short_of(partner)
                .unwrap_or(ShortAddress::COORDINATOR);
            match via {
                Some(r) => {
                    self.zdo
                        .request_via(dst, cluster::SECURITY_START_KEY_NEGOTIATION_REQ, &req, r)
                }
                None => self
                    .zdo
                    .request(dst, cluster::SECURITY_START_KEY_NEGOTIATION_REQ, &req),
            }
            .map_err(|_| ZdpStatus::TemporaryFailure)?;
            self.dlk.session = Some(Session {
                partner,
                ephemeral,
                protocol: method.protocol,
                secret: method.secret,
                via,
                backup,
                deadline: self.now + self.aps.aib.security_timeout_period,
                verifying: false,
            });
            Ok(())
        }
    }

    /// Security_Start_Key_Negotiation_rsp received (APSME-KEY-NEGOTIATE.confirm,
    /// §2.4.4.4.1.4): derives the link key, installs it unverified and
    /// starts the verification (§4.6.3.5 steps 3–4).
    pub(crate) fn on_key_negotiation_response(
        &mut self,
        src_ieee: Option<ExtendedAddress>,
        status: ZdpStatus,
        tlvs: &[u8],
        relayed: Option<RelayInfo>,
    ) {
        #[cfg(not(feature = "dlk"))]
        {
            let _ = (src_ieee, status, tlvs, relayed);
        }
        #[cfg(feature = "dlk")]
        {
            let Some(session) = self.dlk.session.as_ref() else {
                return;
            };
            if src_ieee.is_some_and(|s| s != session.partner) {
                return;
            }
            if status != ZdpStatus::Success {
                // TEMPORARY_FAILURE: the retry (≥ 5 s later) is left to the
                // application; every failure restores the entry (§4.4.9).
                self.abort_key_negotiation();
                return;
            }
            let Some(point) = panweave_zdo::security::validate(tlvs)
                .ok()
                .and_then(|set| PublicPoint::find(&set))
            else {
                return;
            };
            let Some(session) = self.dlk.session.as_mut() else {
                return;
            };
            if point.device != session.partner {
                return;
            }
            let key =
                match session
                    .ephemeral
                    .derive::<C>(self.config.ieee, session.partner, &point.point)
                {
                    Ok(k) => k,
                    Err(_) => {
                        self.abort_key_negotiation();
                        return;
                    }
                };
            let partner = session.partner;
            let secret = session.secret;
            let protocol = session.protocol;
            let via = session.via.or(relayed);
            session.verifying = true;
            session.via = via;
            if self.aps.security.entry(partner).is_none() {
                let e = LinkKeyEntry::provisional(partner, key.clone(), LinkKeyKind::Unique);
                let _ = self.aps.install_link_key(e);
            }
            self.aps.set_negotiated_key(
                partner,
                &key,
                LinkKeyKind::Unique,
                KeyAttributes::UnverifiedKey,
            );
            if let Some(e) = self.aps.security.keys_mut().get_mut(partner) {
                e.negotiation_state = KeyNegotiationState::Complete;
                e.negotiation_method = protocol;
                e.post_join_key_update = update_method(secret);
                if self.phase == Phase::AwaitingKey {
                    e.initial_join_authentication =
                        if secret == SelectedKeyNegotiationMethod::SECRET_ANONYMOUS {
                            InitialJoinAuthentication::AnonymousKeyNegotiation
                        } else {
                            InitialJoinAuthentication::KeyNegotiationWithAuthentication
                        };
                }
            }
            let short = crate::context::AddrView(&self.nwk)
                .short_of(partner)
                .unwrap_or(ShortAddress::COORDINATOR);
            let r = match via {
                Some(relay) if self.phase == Phase::AwaitingKey => {
                    self.aps
                        .verify_key_via(partner, relay.parent, KeyType::TrustCenterLinkKey)
                }
                _ => self
                    .aps
                    .verify_key(partner, short, KeyType::TrustCenterLinkKey),
            };
            if r.is_err() {
                self.abort_key_negotiation();
            }
        }
    }

    /// Confirm Key for a negotiated key: the exchange is complete.
    pub(crate) fn on_key_negotiation_confirmed(&mut self, partner: ExtendedAddress, ok: bool) {
        let Some(session) = self.dlk.session.as_ref() else {
            return;
        };
        if session.partner != partner || !session.verifying {
            return;
        }
        if ok {
            self.dlk.session = None;
            self.push_event(StackEvent::LinkKeyUpdated);
        } else {
            self.abort_key_negotiation();
        }
    }

    /// Discards the negotiation and restores the previous entry (§4.4.9).
    pub(crate) fn abort_key_negotiation(&mut self) {
        let Some(session) = self.dlk.session.take() else {
            return;
        };
        match session.backup {
            Some(e) => {
                let _ = self.aps.install_link_key(e);
            }
            None => {
                let _ = self.aps.security.remove(session.partner);
            }
        }
        self.push_event(StackEvent::KeyNegotiationFailed {
            partner: session.partner,
        });
    }

    /// Trust Center: a joiner that negotiated and verified its key gets
    /// the network key (§4.7.3.3 steps 7–10).
    pub(crate) fn on_joiner_key_verified(
        &mut self,
        device: ExtendedAddress,
        relayed: Option<RelayInfo>,
    ) {
        let Some(i) = self.dlk.joins.iter().position(|j| j.device == device) else {
            return;
        };
        let join = self.dlk.joins.swap_remove(i);
        if let Some(e) = self.aps.security.keys_mut().get_mut(device) {
            // Step 7b: the joiner supports frame counter synchronization.
            e.frame_counter_sync = true;
            // Step 8: a negotiation that used the authentication token
            // locks the entry against further token updates.
            if join.secret == SelectedKeyNegotiationMethod::SECRET_AUTH_TOKEN {
                e.passphrase_update_allowed = false;
            }
        }
        // `join.parent` is the relaying router; None when this Trust
        // Center is the parent (the relay information then names the
        // joiner itself as the relaying hop).
        let _ = relayed;
        let route = match join.parent {
            Some(p) if p != self.nwk.nib.network_address => KeyRoute::Tunnel { parent: p },
            _ => KeyRoute::Direct {
                short: join.short,
                nwk_secure: false,
            },
        };
        self.send_network_key(device, join.short, route);
    }

    /// Expires negotiations and pending joins (§4.7.3.3 steps 4a / 6a,
    /// §4.6.3.5).
    pub(crate) fn poll_dlk(&mut self, now: Instant) {
        if self
            .dlk
            .session
            .as_ref()
            .is_some_and(|s| now.has_reached(s.deadline))
        {
            self.abort_key_negotiation();
        }
        let mut i = 0;
        while i < self.dlk.joins.len() {
            if self
                .dlk
                .joins
                .get(i)
                .is_some_and(|j| now.has_reached(j.deadline))
            {
                let j = self.dlk.joins.swap_remove(i);
                let _ = self.aps.security.remove(j.device);
                self.aps.request_link_key_persistence();
            } else {
                i += 1;
            }
        }
    }

    /// Earliest DLK deadline.
    pub(crate) fn dlk_deadline(&self) -> Option<Instant> {
        let s = self.dlk.session.as_ref().map(|s| s.deadline);
        let j = self
            .dlk
            .joins
            .iter()
            .map(|j| j.deadline)
            .min_by_key(|t| t.as_millis());
        match (s, j) {
            (Some(a), Some(b)) => Some(if a.as_millis() <= b.as_millis() { a } else { b }),
            (a, b) => a.or(b),
        }
    }
}
