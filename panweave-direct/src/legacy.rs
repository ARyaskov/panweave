//! Support for legacy networks (ZD 1.1 §10): a ZDD on a network whose
//! Trust Center predates Zigbee Direct (§6.2.3) never hands the ZVD the
//! network key the Trust Center tunnels to it. Instead it proves the
//! ZVD's authorization itself: an ephemeral authorization key opens an
//! ephemeral authorization session (§10.1) in which only the exchange
//! with the Trust Center passes, the ZDD watches that exchange for the
//! Trust Center's key-load and data-key secured messages, and only then
//! derives and sends the Basic authorization key on the Trust Center's
//! behalf. A Trust Center rejoin (Limited Authorization session, §9.1)
//! is answered with a Basic key derived from the active network key.
//!
//! This module holds the APS-frame inspection the rules need and the
//! session state; the ZDD facade applies them to the NPDUs crossing the
//! Trusted Link.

use panweave_security::aux_header::{KeyIdentifier, SecurityLevel};
use panweave_security::cipher::BlockCipher;
use panweave_security::frame::{peek_aux, unprotect_in_place};
use panweave_security::key_hierarchy;
use panweave_types::{Instant, Key128};

/// APS command identifiers of the Relay Message commands (R23.2 Table
/// 4-35).
const APS_RELAY_MESSAGE_DOWNSTREAM: u8 = 0x11;
const APS_RELAY_MESSAGE_UPSTREAM: u8 = 0x12;

/// Longest tunnelled Transport Key the well-known-key probe copies.
const PROBE_MAX: usize = 96;

/// The APS security applied to a frame, as far as the frame's own
/// headers say.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ApsShape {
    /// The frame is an APS command frame (frame type 01).
    pub command: bool,
    /// The APS command identifier of an unsecured command frame.
    pub command_id: Option<u8>,
    /// The key identifier of the auxiliary header when APS-secured.
    pub key_id: Option<KeyIdentifier>,
    /// Offset of the auxiliary header (secured) or the payload.
    pub header_len: usize,
}

/// Parses the APS frame control, counter and extended header of
/// `aps_frame` (the NWK payload). `None` when too short to tell.
pub fn aps_shape(aps_frame: &[u8]) -> Option<ApsShape> {
    let &fc = aps_frame.first()?;
    let frame_type = fc & 0x03;
    let mut pos = match frame_type {
        // Data frames carry destination endpoint / group, cluster,
        // profile, source endpoint and the counter (§2.2.5.1).
        0x00 => {
            let delivery = (fc >> 2) & 0x03;
            let dst = if delivery == 0x03 { 2 } else { 1 };
            1 + dst + 2 + 2 + 1 + 1
        }
        // Commands: frame control and counter.
        0x01 => 2,
        // Acknowledgements: like data frames without a group address.
        0x02 => {
            if fc & 0x10 != 0 {
                2
            } else {
                1 + 1 + 2 + 2 + 1 + 1
            }
        }
        _ => return None,
    };
    if fc & 0x80 != 0 {
        let ext = aps_frame.get(pos).copied()?;
        pos += if ext.trailing_zeros() >= 2 { 1 } else { 3 };
    }
    let command = frame_type == 0x01;
    if fc & 0x20 != 0 {
        let control = aps_frame.get(pos).copied()?;
        let key_id = match (control >> 3) & 0x03 {
            0 => KeyIdentifier::Data,
            1 => KeyIdentifier::Network,
            2 => KeyIdentifier::KeyTransport,
            _ => KeyIdentifier::KeyLoad,
        };
        Some(ApsShape {
            command,
            command_id: None,
            key_id: Some(key_id),
            header_len: pos,
        })
    } else {
        Some(ApsShape {
            command,
            command_id: command.then(|| aps_frame.get(pos).copied()).flatten(),
            key_id: None,
            header_len: pos,
        })
    }
}

/// The source address of the auxiliary header of an APS-secured frame
/// with an extended nonce (which tells the ZDD's own aliased Transport
/// Keys from the Trust Center's).
pub fn aux_source(aps_frame: &[u8]) -> Option<panweave_types::ExtendedAddress> {
    let shape = aps_shape(aps_frame)?;
    shape.key_id?;
    peek_aux(aps_frame, shape.header_len).ok()?.source
}

/// Whether `aps_frame` is an (unsecured) Relay Message Downstream or
/// Upstream command (§10.1 exception 3).
pub fn is_relay_message(aps_frame: &[u8]) -> bool {
    aps_shape(aps_frame).is_some_and(|s| {
        s.command
            && matches!(
                s.command_id,
                Some(APS_RELAY_MESSAGE_DOWNSTREAM | APS_RELAY_MESSAGE_UPSTREAM)
            )
    })
}

/// Whether the APS-secured frame `aps_frame` was secured under the
/// well-known Trust Center link key "ZigBeeAlliance09" (§10 step 2.1):
/// the ZDD tries the derivative the auxiliary header names on a copy.
/// The auxiliary header must carry the extended nonce (a Transport Key
/// always does). A frame that is not APS-secured, or longer than the
/// probe buffer, does not qualify.
pub fn secured_with_well_known_key<C: BlockCipher>(aps_frame: &[u8], level: SecurityLevel) -> bool {
    let Some(shape) = aps_shape(aps_frame) else {
        return false;
    };
    let Some(key_id) = shape.key_id else {
        return false;
    };
    let Ok(aux) = peek_aux(aps_frame, shape.header_len) else {
        return false;
    };
    let Some(source) = aux.source else {
        return false;
    };
    let well_known = Key128::WELL_KNOWN_GLOBAL_TCLK;
    let derived = match key_id {
        KeyIdentifier::Data => well_known,
        KeyIdentifier::KeyTransport => key_hierarchy::key_transport_key::<C>(&well_known),
        KeyIdentifier::KeyLoad => key_hierarchy::key_load_key::<C>(&well_known),
        KeyIdentifier::Network => return false,
    };
    let mut copy = [0u8; PROBE_MAX];
    let Some(buf) = copy.get_mut(..aps_frame.len()) else {
        return false;
    };
    buf.copy_from_slice(aps_frame);
    let cipher = C::new(&derived);
    unprotect_in_place(&cipher, level, source, buf, shape.header_len).is_ok()
}

/// What an ephemeral authorization session observed in a frame from the
/// Trust Center to the ZVD (§10.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Observation {
    /// APS-secured under a key-load key: end-to-end authentication
    /// between the Trust Center and the ZVD succeeded.
    KeyLoad,
    /// APS-secured under a data key (after key-load): the
    /// authentication sequence completed.
    DataKey,
    /// Nothing of note.
    None,
}

/// Which way an NPDU crosses the Trusted Link.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Direction {
    /// From the ZVD into the network.
    FromZvd,
    /// From the network to the ZVD.
    ToZvd,
}

/// The state of a ZVD attached to a ZDD on a legacy network (§10.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Phase {
    /// An ephemeral authorization session: only the exchange with the
    /// Trust Center passes.
    Ephemeral {
        /// A key-load secured message from the Trust Center was seen.
        authenticated: bool,
    },
    /// Basic authorization: any NPDU passes.
    Basic,
}

/// An ephemeral authorization session (§10.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EphemeralSession {
    /// Its phase.
    pub phase: Phase,
    /// When, without proof of end-to-end authentication, the ZDD
    /// disconnects (`apsSecurityTimeOutPeriod` from establishment).
    pub deadline: Instant,
}

impl EphemeralSession {
    /// A session opened when the ephemeral key was sent.
    pub const fn new(deadline: Instant) -> Self {
        EphemeralSession {
            phase: Phase::Ephemeral {
                authenticated: false,
            },
            deadline,
        }
    }

    /// Whether the session is still ephemeral (not yet Basic).
    pub const fn is_ephemeral(&self) -> bool {
        matches!(self.phase, Phase::Ephemeral { .. })
    }

    /// Whether the disconnect deadline has passed unauthenticated.
    pub fn timed_out(&self, now: Instant) -> bool {
        matches!(
            self.phase,
            Phase::Ephemeral {
                authenticated: false
            }
        ) && now.has_reached(self.deadline)
    }

    /// Whether an NPDU may cross the link (§10.1): in an ephemeral
    /// session only APS frames between the ZVD and the Trust Center
    /// (`peer_is_trust_center`: the NWK destination, resp. source, is
    /// 0x0000) that are APS-secured, or unsecured once end-to-end
    /// authentication succeeded, and Relay Message commands; NWK
    /// command frames never. A Basic session passes everything.
    pub fn allows(
        &self,
        direction: Direction,
        nwk_command: bool,
        peer_is_trust_center: bool,
        aps_frame: &[u8],
    ) -> bool {
        let Phase::Ephemeral { authenticated } = self.phase else {
            return true;
        };
        let _ = direction;
        if nwk_command {
            return false;
        }
        if is_relay_message(aps_frame) {
            return true;
        }
        if !peer_is_trust_center {
            return false;
        }
        match aps_shape(aps_frame) {
            Some(s) if s.key_id.is_some() => true,
            Some(_) => authenticated,
            None => false,
        }
    }

    /// Records what a frame from the Trust Center to the ZVD shows and
    /// reports it; the `DataKey` observation after authentication means
    /// the ZDD now sends the Basic key and the session becomes Basic.
    pub fn observe_from_trust_center(&mut self, aps_frame: &[u8]) -> Observation {
        let Phase::Ephemeral { authenticated } = self.phase else {
            return Observation::None;
        };
        match aps_shape(aps_frame).and_then(|s| s.key_id) {
            Some(KeyIdentifier::KeyLoad) => {
                self.phase = Phase::Ephemeral {
                    authenticated: true,
                };
                Observation::KeyLoad
            }
            Some(KeyIdentifier::Data) if authenticated => {
                self.phase = Phase::Basic;
                Observation::DataKey
            }
            _ => Observation::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_security::cipher::SoftwareAes;
    use panweave_types::Duration;

    #[test]
    fn aps_frames_are_classified() {
        // Unsecured Transport Key command.
        let s = aps_shape(&[0x01, 0x10, 0x05, 0x01]).unwrap();
        assert!(s.command && s.command_id == Some(0x05) && s.key_id.is_none());
        // Secured command, key-load.
        let s = aps_shape(&[0x21, 0x10, 0x18, 0, 0, 0, 0]).unwrap();
        assert_eq!(s.key_id, Some(KeyIdentifier::KeyLoad));
        // Secured data frame, data key.
        let s = aps_shape(&[0x20, 0x01, 0x06, 0x00, 0x04, 0x01, 0x01, 0x10, 0x00]).unwrap();
        assert!(!s.command && s.key_id == Some(KeyIdentifier::Data));
        assert!(is_relay_message(&[0x01, 0x10, 0x12]));
        assert!(!is_relay_message(&[0x01, 0x10, 0x05]));
        assert!(aps_shape(&[]).is_none());
    }

    #[test]
    fn the_well_known_key_probe_recognizes_its_own_frames() {
        use panweave_security::aux_header::{AuxHeader, SecurityControl};
        use panweave_security::frame::protect_in_place;
        use panweave_types::{ExtendedAddress, FrameCounter};
        let src = ExtendedAddress(0x00DD_0000_0000_0001);
        let aux = AuxHeader {
            control: SecurityControl {
                level: SecurityLevel::EncMic32,
                key_id: KeyIdentifier::KeyTransport,
                extended_nonce: true,
            },
            frame_counter: FrameCounter(7),
            source: Some(src),
            key_sequence: None,
        };
        // A Transport Key command (network key) secured with the
        // key-transport key derived from `key`, extended nonce.
        let secure = |key: &Key128| -> ([u8; 64], usize) {
            let mut buf = [0u8; 64];
            buf[0] = 0x21;
            buf[1] = 0x10;
            let header_len = 2;
            let payload = [
                0x05u8, 0x01, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 0,
            ];
            let start = header_len + aux.encoded_len();
            buf[start..start + payload.len()].copy_from_slice(&payload);
            let derived = key_hierarchy::key_transport_key::<SoftwareAes>(key);
            let n = protect_in_place(
                &SoftwareAes::new(&derived),
                &aux,
                src,
                &mut buf,
                header_len,
                payload.len(),
            )
            .unwrap();
            (buf, n)
        };
        let (buf, n) = secure(&Key128::WELL_KNOWN_GLOBAL_TCLK);
        assert!(secured_with_well_known_key::<SoftwareAes>(
            &buf[..n],
            SecurityLevel::EncMic32
        ));
        // Under another key the probe fails; unsecured frames never
        // qualify.
        let (buf, n) = secure(&Key128::from_bytes([3; 16]));
        assert!(!secured_with_well_known_key::<SoftwareAes>(
            &buf[..n],
            SecurityLevel::EncMic32
        ));
        assert!(!secured_with_well_known_key::<SoftwareAes>(
            &[0x01, 0x10, 0x05, 0x01],
            SecurityLevel::EncMic32
        ));
    }

    #[test]
    fn the_ephemeral_session_filters_and_graduates() {
        let t0 = Instant::from_millis(0);
        let mut s = EphemeralSession::new(t0 + Duration::from_secs(10));
        let secured_cmd = [0x21, 0x10, 0x18, 0, 0, 0, 0];
        let unsecured_data = [0x00, 0x01, 0x06, 0x00, 0x04, 0x01, 0x01, 0x10, 0x00];
        // Only APS-secured traffic with the Trust Center, plus relays.
        assert!(s.allows(Direction::FromZvd, false, true, &secured_cmd));
        assert!(!s.allows(Direction::FromZvd, false, false, &secured_cmd));
        assert!(!s.allows(Direction::FromZvd, false, true, &unsecured_data));
        assert!(!s.allows(Direction::ToZvd, true, true, &[0x01, 0x02]));
        assert!(s.allows(Direction::FromZvd, false, false, &[0x01, 0x10, 0x12]));
        assert!(!s.timed_out(t0 + Duration::from_secs(9)));
        assert!(s.timed_out(t0 + Duration::from_secs(10)));
        // A data-key message before key-load proves nothing.
        let secured_data = [
            0x20, 0x01, 0x06, 0x00, 0x04, 0x01, 0x01, 0x10, 0x00, 0, 0, 0, 0,
        ];
        assert_eq!(
            s.observe_from_trust_center(&secured_data),
            Observation::None
        );
        assert_eq!(
            s.observe_from_trust_center(&secured_cmd),
            Observation::KeyLoad
        );
        assert!(s.allows(Direction::FromZvd, false, true, &unsecured_data));
        assert!(!s.timed_out(t0 + Duration::from_secs(60)));
        assert_eq!(
            s.observe_from_trust_center(&secured_data),
            Observation::DataKey
        );
        assert_eq!(s.phase, Phase::Basic);
        assert!(s.allows(Direction::ToZvd, true, false, &[]));
        assert_eq!(s.observe_from_trust_center(&secured_cmd), Observation::None);
    }
}
