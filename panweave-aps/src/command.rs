//! APS command frames (R23.2 §4.4.11).
//!
//! The command identifier follows the APS header (frame control and
//! counter); the auxiliary security header, when present, precedes the
//! command identifier. Key material inside [`TransportKey`] is a
//! [`Key128`] and therefore redacted from `Debug` output.

use panweave_codec::tlv::{TlvSet, write_tlv};
use panweave_codec::{CodecError, Decode, Encode, Reader, Writer};
use panweave_types::{
    ApsStatus, ExtendedAddress, Key128, KeySequenceNumber, KeyType, ShortAddress,
};

/// APS command identifiers (Table 4-31).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ApsCommandId {
    /// Transport Key.
    TransportKey,
    /// Update Device.
    UpdateDevice,
    /// Remove Device.
    RemoveDevice,
    /// Request Key.
    RequestKey,
    /// Switch Key.
    SwitchKey,
    /// Tunnel.
    Tunnel,
    /// Verify Key.
    VerifyKey,
    /// Confirm Key.
    ConfirmKey,
    /// Relay Message Downstream.
    RelayMessageDownstream,
    /// Relay Message Upstream.
    RelayMessageUpstream,
    /// Reserved or unknown identifier.
    Unknown(u8),
}

impl ApsCommandId {
    /// Parses the identifier octet.
    pub const fn from_raw(v: u8) -> Self {
        match v {
            0x05 => ApsCommandId::TransportKey,
            0x06 => ApsCommandId::UpdateDevice,
            0x07 => ApsCommandId::RemoveDevice,
            0x08 => ApsCommandId::RequestKey,
            0x09 => ApsCommandId::SwitchKey,
            0x0E => ApsCommandId::Tunnel,
            0x0F => ApsCommandId::VerifyKey,
            0x10 => ApsCommandId::ConfirmKey,
            0x11 => ApsCommandId::RelayMessageDownstream,
            0x12 => ApsCommandId::RelayMessageUpstream,
            other => ApsCommandId::Unknown(other),
        }
    }

    /// The identifier octet.
    pub const fn raw(self) -> u8 {
        match self {
            ApsCommandId::TransportKey => 0x05,
            ApsCommandId::UpdateDevice => 0x06,
            ApsCommandId::RemoveDevice => 0x07,
            ApsCommandId::RequestKey => 0x08,
            ApsCommandId::SwitchKey => 0x09,
            ApsCommandId::Tunnel => 0x0E,
            ApsCommandId::VerifyKey => 0x0F,
            ApsCommandId::ConfirmKey => 0x10,
            ApsCommandId::RelayMessageDownstream => 0x11,
            ApsCommandId::RelayMessageUpstream => 0x12,
            ApsCommandId::Unknown(v) => v,
        }
    }
}

/// Tag of the Link-Key Features & Capabilities local TLV carried in
/// Transport Key commands (§4.4.11.1.4.1).
pub const TLV_LINK_KEY_FEATURES: u8 = 0x00;

/// Tag of the Relay Message local TLV (§4.4.11.9.2.1.1).
pub const TLV_RELAY_MESSAGE: u8 = 0x00;

/// Key descriptor of a Transport Key command (§4.4.11.1.3).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum KeyDescriptor<'a> {
    /// Trust Center link key (StandardKeyType 0x04).
    TrustCenterLinkKey {
        /// The link key.
        key: Key128,
        /// Device that should use the key.
        destination: ExtendedAddress,
        /// The Trust Center that sent it.
        source: ExtendedAddress,
        /// Optional TLVs (Link-Key Features & Capabilities).
        tlvs: &'a [u8],
    },
    /// Standard network key (StandardKeyType 0x01).
    NetworkKey {
        /// The network key.
        key: Key128,
        /// Key sequence number.
        sequence: KeySequenceNumber,
        /// Device that should use the key (all zeros for broadcasts).
        destination: ExtendedAddress,
        /// Originator (all ones in a distributed security network).
        source: ExtendedAddress,
    },
    /// Application link key (StandardKeyType 0x03).
    ApplicationLinkKey {
        /// The link key.
        key: Key128,
        /// The partner sharing the key.
        partner: ExtendedAddress,
        /// The receiving device requested the key.
        initiator: bool,
        /// Optional TLVs.
        tlvs: &'a [u8],
    },
    /// Basic authorization key of a Zigbee Direct Virtual Device
    /// (StandardKeyType 0xB2, R23.2 §4.6.3.2.2.4 / ZD 1.1 §7.7.4.3): the
    /// key derived from the network key, that key's sequence number,
    /// and the addresses as for a network key (ADR-0017).
    BasicAuthorizationKey {
        /// The Basic authorization key.
        key: Key128,
        /// Sequence number of the network key it derives from.
        sequence: KeySequenceNumber,
        /// The ZVD.
        destination: ExtendedAddress,
        /// The Trust Center (or ZDD on a distributed network).
        source: ExtendedAddress,
    },
}

/// Transport Key command (§4.4.11.1).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransportKey<'a> {
    /// The transported key and its parameters.
    pub descriptor: KeyDescriptor<'a>,
}

impl TransportKey<'_> {
    /// The StandardKeyType octet (Table 4-9).
    pub const fn key_type(&self) -> KeyType {
        match self.descriptor {
            KeyDescriptor::TrustCenterLinkKey { .. } => KeyType::TrustCenterLinkKey,
            KeyDescriptor::NetworkKey { .. } => KeyType::StandardNetworkKey,
            KeyDescriptor::ApplicationLinkKey { .. } => KeyType::ApplicationLinkKey,
            KeyDescriptor::BasicAuthorizationKey { .. } => KeyType::BasicAuthorization,
        }
    }
}

/// Link-Key Features & Capabilities TLV value: bit 0 = APS frame counter
/// synchronization supported (Table 4-36 bit 0, §4.4.11.1.4.1).
pub const LINK_KEY_FEATURE_FRAME_COUNTER_SYNC: u8 = 0x01;

impl<'a> Decode<'a> for TransportKey<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let key_type = KeyType::from_raw(r.u8()?);
        let key = Key128::from_bytes(r.array::<16>()?);
        let descriptor = match key_type {
            KeyType::TrustCenterLinkKey => {
                let destination = ExtendedAddress(r.u64_le()?);
                let source = ExtendedAddress(r.u64_le()?);
                let tlvs = r.take_rest();
                if !tlvs.is_empty() {
                    TlvSet::validate(tlvs, |_| false)?;
                }
                KeyDescriptor::TrustCenterLinkKey {
                    key,
                    destination,
                    source,
                    tlvs,
                }
            }
            KeyType::StandardNetworkKey => KeyDescriptor::NetworkKey {
                key,
                sequence: KeySequenceNumber(r.u8()?),
                destination: ExtendedAddress(r.u64_le()?),
                source: ExtendedAddress(r.u64_le()?),
            },
            KeyType::BasicAuthorization => KeyDescriptor::BasicAuthorizationKey {
                key,
                sequence: KeySequenceNumber(r.u8()?),
                destination: ExtendedAddress(r.u64_le()?),
                source: ExtendedAddress(r.u64_le()?),
            },
            KeyType::ApplicationLinkKey => {
                let partner = ExtendedAddress(r.u64_le()?);
                let initiator = r.u8()? & 0x01 != 0;
                let tlvs = r.take_rest();
                if !tlvs.is_empty() {
                    TlvSet::validate(tlvs, |_| false)?;
                }
                KeyDescriptor::ApplicationLinkKey {
                    key,
                    partner,
                    initiator,
                    tlvs,
                }
            }
            _ => {
                return Err(CodecError::Unsupported {
                    what: "transport key type",
                });
            }
        };
        Ok(TransportKey { descriptor })
    }
}

impl Encode for TransportKey<'_> {
    fn encoded_len(&self) -> usize {
        1 + 16
            + match &self.descriptor {
                KeyDescriptor::TrustCenterLinkKey { tlvs, .. } => 8 + 8 + tlvs.len(),
                KeyDescriptor::NetworkKey { .. } | KeyDescriptor::BasicAuthorizationKey { .. } => {
                    1 + 8 + 8
                }
                KeyDescriptor::ApplicationLinkKey { tlvs, .. } => 8 + 1 + tlvs.len(),
            }
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.key_type().raw())?;
        match &self.descriptor {
            KeyDescriptor::TrustCenterLinkKey {
                key,
                destination,
                source,
                tlvs,
            } => {
                w.bytes(key.as_bytes())?;
                w.u64_le(destination.0)?;
                w.u64_le(source.0)?;
                w.bytes(tlvs)
            }
            KeyDescriptor::NetworkKey {
                key,
                sequence,
                destination,
                source,
            }
            | KeyDescriptor::BasicAuthorizationKey {
                key,
                sequence,
                destination,
                source,
            } => {
                w.bytes(key.as_bytes())?;
                w.u8(sequence.0)?;
                w.u64_le(destination.0)?;
                w.u64_le(source.0)
            }
            KeyDescriptor::ApplicationLinkKey {
                key,
                partner,
                initiator,
                tlvs,
            } => {
                w.bytes(key.as_bytes())?;
                w.u64_le(partner.0)?;
                w.u8(u8::from(*initiator))?;
                w.bytes(tlvs)
            }
        }
    }
}

/// Writes a Link-Key Features & Capabilities TLV.
pub fn write_link_key_features(w: &mut Writer<'_>, features: u8) -> Result<(), CodecError> {
    write_tlv(w, TLV_LINK_KEY_FEATURES, &[features])
}

/// Device status of an Update Device command (Table 4-14).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum UpdateDeviceStatus {
    /// Standard device secured rejoin.
    SecuredRejoin,
    /// Standard device unsecured join.
    UnsecuredJoin,
    /// Device left.
    DeviceLeft,
    /// Standard device Trust Center rejoin.
    TrustCenterRejoin,
    /// Reserved value (0x04–0xFF).
    Reserved(u8),
}

impl UpdateDeviceStatus {
    /// Parses the octet.
    pub const fn from_raw(v: u8) -> Self {
        match v {
            0x00 => UpdateDeviceStatus::SecuredRejoin,
            0x01 => UpdateDeviceStatus::UnsecuredJoin,
            0x02 => UpdateDeviceStatus::DeviceLeft,
            0x03 => UpdateDeviceStatus::TrustCenterRejoin,
            other => UpdateDeviceStatus::Reserved(other),
        }
    }

    /// The octet.
    pub const fn raw(self) -> u8 {
        match self {
            UpdateDeviceStatus::SecuredRejoin => 0x00,
            UpdateDeviceStatus::UnsecuredJoin => 0x01,
            UpdateDeviceStatus::DeviceLeft => 0x02,
            UpdateDeviceStatus::TrustCenterRejoin => 0x03,
            UpdateDeviceStatus::Reserved(v) => v,
        }
    }
}

/// Update Device command (§4.4.11.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct UpdateDevice<'a> {
    /// The device whose status changed.
    pub device: ExtendedAddress,
    /// Its network address.
    pub short: ShortAddress,
    /// The new status.
    pub status: UpdateDeviceStatus,
    /// Joiner TLVs relayed from Network Commissioning (may be empty).
    pub joiner_tlvs: &'a [u8],
}

impl<'a> Decode<'a> for UpdateDevice<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let device = ExtendedAddress(r.u64_le()?);
        let short = ShortAddress(r.u16_le()?);
        let status = UpdateDeviceStatus::from_raw(r.u8()?);
        let joiner_tlvs = r.take_rest();
        if !joiner_tlvs.is_empty() {
            TlvSet::validate(joiner_tlvs, |_| false)?;
        }
        Ok(UpdateDevice {
            device,
            short,
            status,
            joiner_tlvs,
        })
    }
}

impl Encode for UpdateDevice<'_> {
    fn encoded_len(&self) -> usize {
        8 + 2 + 1 + self.joiner_tlvs.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u64_le(self.device.0)?;
        w.u16_le(self.short.0)?;
        w.u8(self.status.raw())?;
        w.bytes(self.joiner_tlvs)
    }
}

/// Remove Device command (§4.4.11.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RemoveDevice {
    /// The device to remove.
    pub target: ExtendedAddress,
}

impl<'a> Decode<'a> for RemoveDevice {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(RemoveDevice {
            target: ExtendedAddress(r.u64_le()?),
        })
    }
}

impl Encode for RemoveDevice {
    fn encoded_len(&self) -> usize {
        8
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u64_le(self.target.0)
    }
}

/// RequestKeyType of a Request Key command (Table 4-19).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RequestKeyType {
    /// Application link key (0x02); the partner address is present.
    ApplicationLinkKey,
    /// Trust Center link key (0x04).
    TrustCenterLinkKey,
    /// Any other value.
    Unknown(u8),
}

impl RequestKeyType {
    /// Parses the octet.
    pub const fn from_raw(v: u8) -> Self {
        match v {
            0x02 => RequestKeyType::ApplicationLinkKey,
            0x04 => RequestKeyType::TrustCenterLinkKey,
            other => RequestKeyType::Unknown(other),
        }
    }

    /// The octet.
    pub const fn raw(self) -> u8 {
        match self {
            RequestKeyType::ApplicationLinkKey => 0x02,
            RequestKeyType::TrustCenterLinkKey => 0x04,
            RequestKeyType::Unknown(v) => v,
        }
    }
}

/// Request Key command (§4.4.11.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RequestKey {
    /// Requested key type.
    pub key_type: RequestKeyType,
    /// Partner address (application link keys only).
    pub partner: Option<ExtendedAddress>,
}

impl<'a> Decode<'a> for RequestKey {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let key_type = RequestKeyType::from_raw(r.u8()?);
        let partner = match key_type {
            RequestKeyType::ApplicationLinkKey => Some(ExtendedAddress(r.u64_le()?)),
            // Tolerate a partner address on other types; unknown types
            // are dropped by the receiver anyway (§4.4.5.2.3).
            _ => {
                if r.remaining() >= 8 {
                    Some(ExtendedAddress(r.u64_le()?))
                } else {
                    None
                }
            }
        };
        Ok(RequestKey { key_type, partner })
    }
}

impl Encode for RequestKey {
    fn encoded_len(&self) -> usize {
        1 + if self.key_type == RequestKeyType::ApplicationLinkKey {
            8
        } else {
            0
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.key_type.raw())?;
        if self.key_type == RequestKeyType::ApplicationLinkKey {
            w.u64_le(
                self.partner
                    .ok_or(CodecError::Unrepresentable { field: "partner" })?
                    .0,
            )?;
        }
        Ok(())
    }
}

/// Switch Key command (§4.4.11.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SwitchKey {
    /// Sequence number of the network key to activate.
    pub sequence: KeySequenceNumber,
}

impl<'a> Decode<'a> for SwitchKey {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(SwitchKey {
            sequence: KeySequenceNumber(r.u8()?),
        })
    }
}

impl Encode for SwitchKey {
    fn encoded_len(&self) -> usize {
        1
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.sequence.0)
    }
}

/// Tunnel command (§4.4.11.6). The tunneled frame is the complete
/// secured APS command frame (its APS header, auxiliary header, encrypted
/// command and MIC) that the parent forwards to `destination` verbatim
/// (§4.6.3.7.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Tunnel<'a> {
    /// The joiner that receives the tunneled command.
    pub destination: ExtendedAddress,
    /// The embedded secured APS frame.
    pub tunneled: &'a [u8],
}

impl<'a> Decode<'a> for Tunnel<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let destination = ExtendedAddress(r.u64_le()?);
        let tunneled = r.take_rest();
        // Frame control + counter + 5-octet auxiliary header minimum.
        if tunneled.len() < 2 + 5 {
            return Err(CodecError::Truncated {
                needed: 2 + 5,
                available: tunneled.len(),
            });
        }
        Ok(Tunnel {
            destination,
            tunneled,
        })
    }
}

impl Encode for Tunnel<'_> {
    fn encoded_len(&self) -> usize {
        8 + self.tunneled.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u64_le(self.destination.0)?;
        w.bytes(self.tunneled)
    }
}

/// Verify Key command (§4.4.11.7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct VerifyKey {
    /// Type of key being verified.
    pub key_type: KeyType,
    /// The initiator's address.
    pub source: ExtendedAddress,
    /// Initiator Verify-Key hash (Annex B.1.4 keyed hash of `0x03`).
    pub hash: [u8; 16],
}

impl<'a> Decode<'a> for VerifyKey {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(VerifyKey {
            key_type: KeyType::from_raw(r.u8()?),
            source: ExtendedAddress(r.u64_le()?),
            hash: r.array::<16>()?,
        })
    }
}

impl Encode for VerifyKey {
    fn encoded_len(&self) -> usize {
        1 + 8 + 16
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.key_type.raw())?;
        w.u64_le(self.source.0)?;
        w.bytes(&self.hash)
    }
}

/// Confirm Key command (§4.4.11.8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConfirmKey {
    /// Result of the verification.
    pub status: ApsStatus,
    /// Type of key verified.
    pub key_type: KeyType,
    /// The device that sent the Verify Key command.
    pub destination: ExtendedAddress,
}

impl<'a> Decode<'a> for ConfirmKey {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(ConfirmKey {
            status: ApsStatus::from_raw(r.u8()?),
            key_type: KeyType::from_raw(r.u8()?),
            destination: ExtendedAddress(r.u64_le()?),
        })
    }
}

impl Encode for ConfirmKey {
    fn encoded_len(&self) -> usize {
        1 + 1 + 8
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.status.raw())?;
        w.u8(self.key_type.raw())?;
        w.u64_le(self.destination.0)
    }
}

/// Relay Message Downstream / Upstream command (§4.4.11.9, §4.4.11.10).
/// Both carry a Relay Message local TLV with the joiner's EUI-64
/// (destination when downstream, source when upstream) and the complete
/// APS frame to relay.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RelayMessage<'a> {
    /// The unauthorized neighbour the message is relayed to or from.
    pub joiner: ExtendedAddress,
    /// The relayed APS frame (starting with its APS header).
    pub message: &'a [u8],
}

impl<'a> Decode<'a> for RelayMessage<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let bytes = r.take_rest();
        let set = TlvSet::validate(bytes, |_| false)?;
        let relay = set.require(TLV_RELAY_MESSAGE)?;
        let mut rr = Reader::new(relay.value);
        let joiner = ExtendedAddress(rr.u64_le()?);
        let message = rr.take_rest();
        if message.len() < 2 {
            return Err(CodecError::Truncated {
                needed: 2,
                available: message.len(),
            });
        }
        Ok(RelayMessage { joiner, message })
    }
}

impl Encode for RelayMessage<'_> {
    fn encoded_len(&self) -> usize {
        2 + 8 + self.message.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let len = 8 + self.message.len();
        if len == 0 || len > 256 {
            return Err(CodecError::Unrepresentable {
                field: "relay message",
            });
        }
        w.u8(TLV_RELAY_MESSAGE)?;
        // The TLV length field encodes length - 1.
        #[allow(clippy::cast_possible_truncation)]
        w.u8((len - 1) as u8)?;
        w.u64_le(self.joiner.0)?;
        w.bytes(self.message)
    }
}

/// A decoded APS command payload.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ApsCommand<'a> {
    /// Transport Key.
    TransportKey(TransportKey<'a>),
    /// Update Device.
    UpdateDevice(UpdateDevice<'a>),
    /// Remove Device.
    RemoveDevice(RemoveDevice),
    /// Request Key.
    RequestKey(RequestKey),
    /// Switch Key.
    SwitchKey(SwitchKey),
    /// Tunnel.
    Tunnel(Tunnel<'a>),
    /// Verify Key.
    VerifyKey(VerifyKey),
    /// Confirm Key.
    ConfirmKey(ConfirmKey),
    /// Relay Message Downstream.
    RelayDownstream(RelayMessage<'a>),
    /// Relay Message Upstream.
    RelayUpstream(RelayMessage<'a>),
}

impl ApsCommand<'_> {
    /// The command identifier.
    pub const fn id(&self) -> ApsCommandId {
        match self {
            ApsCommand::TransportKey(_) => ApsCommandId::TransportKey,
            ApsCommand::UpdateDevice(_) => ApsCommandId::UpdateDevice,
            ApsCommand::RemoveDevice(_) => ApsCommandId::RemoveDevice,
            ApsCommand::RequestKey(_) => ApsCommandId::RequestKey,
            ApsCommand::SwitchKey(_) => ApsCommandId::SwitchKey,
            ApsCommand::Tunnel(_) => ApsCommandId::Tunnel,
            ApsCommand::VerifyKey(_) => ApsCommandId::VerifyKey,
            ApsCommand::ConfirmKey(_) => ApsCommandId::ConfirmKey,
            ApsCommand::RelayDownstream(_) => ApsCommandId::RelayMessageDownstream,
            ApsCommand::RelayUpstream(_) => ApsCommandId::RelayMessageUpstream,
        }
    }
}

impl<'a> Decode<'a> for ApsCommand<'a> {
    /// Decodes the command identifier and payload. Unknown identifiers
    /// yield [`CodecError::Unsupported`].
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let id = ApsCommandId::from_raw(r.u8()?);
        Ok(match id {
            ApsCommandId::TransportKey => ApsCommand::TransportKey(TransportKey::decode(r)?),
            ApsCommandId::UpdateDevice => ApsCommand::UpdateDevice(UpdateDevice::decode(r)?),
            ApsCommandId::RemoveDevice => ApsCommand::RemoveDevice(RemoveDevice::decode(r)?),
            ApsCommandId::RequestKey => ApsCommand::RequestKey(RequestKey::decode(r)?),
            ApsCommandId::SwitchKey => ApsCommand::SwitchKey(SwitchKey::decode(r)?),
            ApsCommandId::Tunnel => ApsCommand::Tunnel(Tunnel::decode(r)?),
            ApsCommandId::VerifyKey => ApsCommand::VerifyKey(VerifyKey::decode(r)?),
            ApsCommandId::ConfirmKey => ApsCommand::ConfirmKey(ConfirmKey::decode(r)?),
            ApsCommandId::RelayMessageDownstream => {
                ApsCommand::RelayDownstream(RelayMessage::decode(r)?)
            }
            ApsCommandId::RelayMessageUpstream => {
                ApsCommand::RelayUpstream(RelayMessage::decode(r)?)
            }
            ApsCommandId::Unknown(_) => {
                return Err(CodecError::Unsupported {
                    what: "APS command",
                });
            }
        })
    }
}

impl Encode for ApsCommand<'_> {
    fn encoded_len(&self) -> usize {
        1 + match self {
            ApsCommand::TransportKey(c) => c.encoded_len(),
            ApsCommand::UpdateDevice(c) => c.encoded_len(),
            ApsCommand::RemoveDevice(c) => c.encoded_len(),
            ApsCommand::RequestKey(c) => c.encoded_len(),
            ApsCommand::SwitchKey(c) => c.encoded_len(),
            ApsCommand::Tunnel(c) => c.encoded_len(),
            ApsCommand::VerifyKey(c) => c.encoded_len(),
            ApsCommand::ConfirmKey(c) => c.encoded_len(),
            ApsCommand::RelayDownstream(c) | ApsCommand::RelayUpstream(c) => c.encoded_len(),
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.id().raw())?;
        match self {
            ApsCommand::TransportKey(c) => c.encode(w),
            ApsCommand::UpdateDevice(c) => c.encode(w),
            ApsCommand::RemoveDevice(c) => c.encode(w),
            ApsCommand::RequestKey(c) => c.encode(w),
            ApsCommand::SwitchKey(c) => c.encode(w),
            ApsCommand::Tunnel(c) => c.encode(w),
            ApsCommand::VerifyKey(c) => c.encode(w),
            ApsCommand::ConfirmKey(c) => c.encode(w),
            ApsCommand::RelayDownstream(c) | ApsCommand::RelayUpstream(c) => c.encode(w),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(cmd: &ApsCommand<'_>) -> heapless::Vec<u8, 160> {
        let mut buf = [0u8; 160];
        let n = cmd.encode_to_slice(&mut buf).unwrap();
        assert_eq!(n, cmd.encoded_len());
        let decoded = ApsCommand::decode_exact(&buf[..n]).unwrap();
        assert_eq!(&decoded, cmd);
        heapless::Vec::from_slice(&buf[..n]).unwrap()
    }

    #[test]
    fn transport_key_variants() {
        let nwk = ApsCommand::TransportKey(TransportKey {
            descriptor: KeyDescriptor::NetworkKey {
                key: Key128::from_bytes([7; 16]),
                sequence: KeySequenceNumber(3),
                destination: ExtendedAddress(0x1122),
                source: ExtendedAddress(0xAABB),
            },
        });
        let bytes = round_trip(&nwk);
        assert_eq!(bytes[0], 0x05);
        assert_eq!(bytes[1], 0x01);
        assert_eq!(bytes[18], 3);
        assert_eq!(bytes.len(), 1 + 1 + 16 + 1 + 8 + 8);

        let mut tlv = [0u8; 3];
        let mut w = Writer::new(&mut tlv);
        write_link_key_features(&mut w, LINK_KEY_FEATURE_FRAME_COUNTER_SYNC).unwrap();
        let tclk = ApsCommand::TransportKey(TransportKey {
            descriptor: KeyDescriptor::TrustCenterLinkKey {
                key: Key128::from_bytes([1; 16]),
                destination: ExtendedAddress(1),
                source: ExtendedAddress(2),
                tlvs: &tlv,
            },
        });
        let bytes = round_trip(&tclk);
        assert_eq!(bytes[1], 0x04);
        assert_eq!(&bytes[bytes.len() - 3..], &[0x00, 0x00, 0x01]);

        let app = ApsCommand::TransportKey(TransportKey {
            descriptor: KeyDescriptor::ApplicationLinkKey {
                key: Key128::from_bytes([2; 16]),
                partner: ExtendedAddress(9),
                initiator: true,
                tlvs: &[],
            },
        });
        let bytes = round_trip(&app);
        assert_eq!(bytes[1], 0x03);
        assert_eq!(bytes[bytes.len() - 1], 1);

        // Unsupported key type.
        assert!(ApsCommand::decode_exact(&[0x05, 0x02, 0, 0]).is_err());
    }

    #[test]
    fn device_management_commands() {
        round_trip(&ApsCommand::UpdateDevice(UpdateDevice {
            device: ExtendedAddress(0x1234),
            short: ShortAddress(0x5678),
            status: UpdateDeviceStatus::UnsecuredJoin,
            joiner_tlvs: &[0x40, 0x03, 0x01, 0x00, 0x00, 0x00],
        }));
        round_trip(&ApsCommand::RemoveDevice(RemoveDevice {
            target: ExtendedAddress(5),
        }));
        let b = round_trip(&ApsCommand::RequestKey(RequestKey {
            key_type: RequestKeyType::TrustCenterLinkKey,
            partner: None,
        }));
        assert_eq!(b.as_slice(), &[0x08, 0x04]);
        round_trip(&ApsCommand::RequestKey(RequestKey {
            key_type: RequestKeyType::ApplicationLinkKey,
            partner: Some(ExtendedAddress(0xF00D)),
        }));
        assert_eq!(
            round_trip(&ApsCommand::SwitchKey(SwitchKey {
                sequence: KeySequenceNumber(4),
            }))
            .as_slice(),
            &[0x09, 4]
        );
        round_trip(&ApsCommand::Tunnel(Tunnel {
            destination: ExtendedAddress(0xBEEF),
            tunneled: &[0x21, 0x05, 0x30, 1, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        }));
        round_trip(&ApsCommand::VerifyKey(VerifyKey {
            key_type: KeyType::TrustCenterLinkKey,
            source: ExtendedAddress(0x77),
            hash: [0xAB; 16],
        }));
        round_trip(&ApsCommand::ConfirmKey(ConfirmKey {
            status: ApsStatus::Success,
            key_type: KeyType::TrustCenterLinkKey,
            destination: ExtendedAddress(0x77),
        }));
    }

    #[test]
    fn relay_message_tlv() {
        let cmd = ApsCommand::RelayUpstream(RelayMessage {
            joiner: ExtendedAddress(0x0102_0304_0506_0708),
            message: &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA],
        });
        let b = round_trip(&cmd);
        assert_eq!(b[0], 0x12);
        assert_eq!(b[1], 0x00);
        assert_eq!(b[2], (8 + 9 - 1) as u8);
        // Missing relay TLV.
        assert!(ApsCommand::decode_exact(&[0x11, 0x01, 0x00, 0xFF]).is_err());
    }

    #[test]
    fn unknown_command_is_unsupported() {
        assert!(matches!(
            ApsCommand::decode_exact(&[0x0A, 1, 2]),
            Err(CodecError::Unsupported { .. })
        ));
    }
}
