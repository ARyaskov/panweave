//! Global TLVs (R23.2 Annex I.4) used by NWK commands, beacons, ZDP and
//! APS security commands.
//!
//! Each typed TLV validates its minimum length (Annex I.2.5) and ignores
//! extension bytes beyond the known fields (Annex I.2.4).

use panweave_codec::error::TlvError;
use panweave_codec::tlv::{self, Tlv, TlvSet};
use panweave_codec::{CodecError, Writer};
use panweave_types::{ChannelMask, ExtendedAddress, PanId, ShortAddress};

/// Global TLV tag identifiers (Table I-3).
pub mod tag {
    /// Manufacturer Specific.
    pub const MANUFACTURER_SPECIFIC: u8 = 64;
    /// Supported Key Negotiation Methods.
    pub const SUPPORTED_KEY_NEGOTIATION_METHODS: u8 = 65;
    /// PAN ID Conflict Report.
    pub const PAN_ID_CONFLICT_REPORT: u8 = 66;
    /// Next PAN ID Change.
    pub const NEXT_PAN_ID_CHANGE: u8 = 67;
    /// Next Channel Change.
    pub const NEXT_CHANNEL_CHANGE: u8 = 68;
    /// Symmetric Passphrase.
    pub const SYMMETRIC_PASSPHRASE: u8 = 69;
    /// Router Information.
    pub const ROUTER_INFORMATION: u8 = 70;
    /// Fragmentation Parameters.
    pub const FRAGMENTATION_PARAMETERS: u8 = 71;
    /// Joiner Encapsulation.
    pub const JOINER_ENCAPSULATION: u8 = 72;
    /// Beacon Appendix Encapsulation.
    pub const BEACON_APPENDIX_ENCAPSULATION: u8 = 73;
    /// BDB Encapsulation (BDB 3.1).
    pub const BDB_ENCAPSULATION: u8 = 74;
    /// Configuration Parameters.
    pub const CONFIGURATION_PARAMETERS: u8 = 75;
    /// Device Capability Extension.
    pub const DEVICE_CAPABILITY_EXTENSION: u8 = 76;
}

fn too_short(t: &Tlv<'_>, min: usize) -> Result<(), TlvError> {
    if t.value.len() < min {
        Err(TlvError::Malformed { tag: t.tag })
    } else {
        Ok(())
    }
}

/// Supported Key Negotiation Methods (ID 65, Annex I.4.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SupportedKeyNegotiationMethods {
    /// Key negotiation protocols bitmask (Table I-4): bit 0 static key
    /// request, bit 1 SPEKE/Curve25519/AES-MMO-128, bit 2
    /// SPEKE/Curve25519/SHA-256.
    pub protocols: u8,
    /// Pre-shared secrets bitmask (Table I-5): bit 0 symmetric
    /// authentication token, bit 1 install code key, bit 2 passcode key,
    /// bit 3 basic access key, bit 4 administrative access key.
    pub secrets: u8,
    /// Source device EUI-64 (absent in the 2-octet minimum form).
    pub source: Option<ExtendedAddress>,
}

impl SupportedKeyNegotiationMethods {
    /// Bit 0 of `protocols`.
    pub const PROTO_STATIC_KEY_REQUEST: u8 = 1 << 0;
    /// Bit 1 of `protocols`.
    pub const PROTO_SPEKE_CURVE25519_AES_MMO: u8 = 1 << 1;
    /// Bit 2 of `protocols`.
    pub const PROTO_SPEKE_CURVE25519_SHA256: u8 = 1 << 2;
    /// Bit 0 of `secrets`.
    pub const SECRET_AUTH_TOKEN: u8 = 1 << 0;
    /// Bit 1 of `secrets`.
    pub const SECRET_INSTALL_CODE: u8 = 1 << 1;
    /// Bit 2 of `secrets`.
    pub const SECRET_PASSCODE: u8 = 1 << 2;

    /// Parses the TLV value.
    pub fn parse(t: &Tlv<'_>) -> Result<Self, TlvError> {
        too_short(t, 2)?;
        let source = t.value.get(2..10).map(|b| {
            let mut a = [0u8; 8];
            a.copy_from_slice(b);
            ExtendedAddress::from_le_bytes(a)
        });
        Ok(SupportedKeyNegotiationMethods {
            protocols: *t.value.first().unwrap_or(&0),
            secrets: *t.value.get(1).unwrap_or(&0),
            source,
        })
    }

    /// Writes the TLV.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        tlv::write_tlv_with(w, tag::SUPPORTED_KEY_NEGOTIATION_METHODS, |w| {
            w.u8(self.protocols)?;
            w.u8(self.secrets)?;
            if let Some(s) = self.source {
                w.u64_le(s.0)?;
            }
            Ok(())
        })
    }

    /// True when any asymmetric (SPEKE) method is offered.
    pub const fn offers_key_negotiation(&self) -> bool {
        self.protocols
            & (Self::PROTO_SPEKE_CURVE25519_AES_MMO | Self::PROTO_SPEKE_CURVE25519_SHA256)
            != 0
    }
}

/// PAN ID Conflict Report (ID 66): `nwkPanIdConflictCount`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PanIdConflictReport {
    /// Number of conflicts detected.
    pub count: u16,
}

impl PanIdConflictReport {
    /// Parses the TLV value.
    pub fn parse(t: &Tlv<'_>) -> Result<Self, TlvError> {
        too_short(t, 2)?;
        Ok(PanIdConflictReport {
            count: u16::from_le_bytes([t.value[0], t.value[1]]),
        })
    }

    /// Writes the TLV.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        tlv::write_tlv(w, tag::PAN_ID_CONFLICT_REPORT, &self.count.to_le_bytes())
    }
}

/// Next PAN ID Change (ID 67).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NextPanIdChange {
    /// The PAN ID to switch to.
    pub pan_id: PanId,
}

impl NextPanIdChange {
    /// Parses the TLV value.
    pub fn parse(t: &Tlv<'_>) -> Result<Self, TlvError> {
        too_short(t, 2)?;
        Ok(NextPanIdChange {
            pan_id: PanId(u16::from_le_bytes([t.value[0], t.value[1]])),
        })
    }

    /// Writes the TLV.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        tlv::write_tlv(w, tag::NEXT_PAN_ID_CHANGE, &self.pan_id.0.to_le_bytes())
    }
}

/// Next Channel Change (ID 68): a channel mask with page bits, exactly
/// one channel set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NextChannelChange {
    /// Channel mask including page (top 5 bits).
    pub mask: ChannelMask,
}

impl NextChannelChange {
    /// Parses the TLV value.
    pub fn parse(t: &Tlv<'_>) -> Result<Self, TlvError> {
        too_short(t, 4)?;
        Ok(NextChannelChange {
            mask: ChannelMask(u32::from_le_bytes([
                t.value[0], t.value[1], t.value[2], t.value[3],
            ])),
        })
    }

    /// Writes the TLV.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        tlv::write_tlv(w, tag::NEXT_CHANNEL_CHANGE, &self.mask.0.to_le_bytes())
    }
}

/// Symmetric Passphrase (ID 69): 16 octets.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SymmetricPassphrase {
    /// The passphrase bytes.
    pub value: [u8; 16],
}

impl core::fmt::Debug for SymmetricPassphrase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SymmetricPassphrase([REDACTED])")
    }
}

impl SymmetricPassphrase {
    /// Parses the TLV value.
    pub fn parse(t: &Tlv<'_>) -> Result<Self, TlvError> {
        too_short(t, 16)?;
        let mut value = [0u8; 16];
        value.copy_from_slice(&t.value[..16]);
        Ok(SymmetricPassphrase { value })
    }

    /// Writes the TLV.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        tlv::write_tlv(w, tag::SYMMETRIC_PASSPHRASE, &self.value)
    }
}

/// Router Information (ID 70, Table I-6).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RouterInformation(pub u16);

impl RouterInformation {
    /// Bit 0: hub connectivity.
    pub const HUB_CONNECTIVITY: u16 = 1 << 0;
    /// Bit 1: uptime > 24 h.
    pub const LONG_UPTIME: u16 = 1 << 1;
    /// Bit 2: preferred parent.
    pub const PREFERRED_PARENT: u16 = 1 << 2;
    /// Bit 3: battery backup.
    pub const BATTERY_BACKUP: u16 = 1 << 3;
    /// Bit 4: enhanced beacon request support.
    pub const ENHANCED_BEACON_REQUEST: u16 = 1 << 4;
    /// Bit 5: MAC data poll keepalive support.
    pub const MAC_DATA_POLL_KEEPALIVE: u16 = 1 << 5;
    /// Bit 6: end device timeout request keepalive support.
    pub const END_DEVICE_KEEPALIVE: u16 = 1 << 6;
    /// Bit 7: power negotiation support.
    pub const POWER_NEGOTIATION: u16 = 1 << 7;

    /// Parses the TLV value.
    pub fn parse(t: &Tlv<'_>) -> Result<Self, TlvError> {
        too_short(t, 2)?;
        Ok(RouterInformation(u16::from_le_bytes([
            t.value[0], t.value[1],
        ])))
    }

    /// Writes the TLV.
    pub fn write(self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        tlv::write_tlv(w, tag::ROUTER_INFORMATION, &self.0.to_le_bytes())
    }

    /// Hub connectivity bit.
    pub const fn hub_connectivity(self) -> bool {
        self.0 & Self::HUB_CONNECTIVITY != 0
    }

    /// Long uptime bit.
    pub const fn long_uptime(self) -> bool {
        self.0 & Self::LONG_UPTIME != 0
    }

    /// Preferred parent bit.
    pub const fn preferred_parent(self) -> bool {
        self.0 & Self::PREFERRED_PARENT != 0
    }
}

/// Fragmentation Parameters (ID 71, Table I-7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct FragmentationParameters {
    /// Node the parameters apply to.
    pub node: ShortAddress,
    /// Fragmentation options (bit 0: application fragmentation supported).
    pub options: u8,
    /// Maximum incoming transfer unit (`apsMaxSizeASDU`).
    pub max_incoming_transfer_unit: u16,
}

impl FragmentationParameters {
    /// Parses the TLV value.
    pub fn parse(t: &Tlv<'_>) -> Result<Self, TlvError> {
        too_short(t, 5)?;
        Ok(FragmentationParameters {
            node: ShortAddress(u16::from_le_bytes([t.value[0], t.value[1]])),
            options: t.value[2],
            max_incoming_transfer_unit: u16::from_le_bytes([t.value[3], t.value[4]]),
        })
    }

    /// Writes the TLV.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        tlv::write_tlv_with(w, tag::FRAGMENTATION_PARAMETERS, |w| {
            w.u16_le(self.node.0)?;
            w.u8(self.options)?;
            w.u16_le(self.max_incoming_transfer_unit)
        })
    }
}

/// Configuration Parameters (ID 75, Table I-8).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConfigurationParameters(pub u16);

impl ConfigurationParameters {
    /// Bit 0: `apsZdoRestrictedMode`.
    pub const ZDO_RESTRICTED_MODE: u16 = 1 << 0;
    /// Bit 1: `requireLinkKeyEncryptionForApsTransportKey`.
    pub const REQUIRE_LINK_KEY_FOR_TRANSPORT_KEY: u16 = 1 << 1;
    /// Bit 2: `nwkLeaveRequestAllowed`.
    pub const LEAVE_REQUEST_ALLOWED: u16 = 1 << 2;

    /// Parses the TLV value.
    pub fn parse(t: &Tlv<'_>) -> Result<Self, TlvError> {
        too_short(t, 2)?;
        Ok(ConfigurationParameters(u16::from_le_bytes([
            t.value[0], t.value[1],
        ])))
    }

    /// Writes the TLV.
    pub fn write(self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        tlv::write_tlv(w, tag::CONFIGURATION_PARAMETERS, &self.0.to_le_bytes())
    }
}

/// Device Capability Extension (ID 76): 2-octet bitmask (bit 0 = Zigbee
/// Direct virtual device per ZD1.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceCapabilityExtension(pub u16);

impl DeviceCapabilityExtension {
    /// Bit 0: the device is a Zigbee Direct Virtual Device.
    pub const ZIGBEE_DIRECT_VIRTUAL_DEVICE: u16 = 1 << 0;

    /// Parses the TLV value.
    pub fn parse(t: &Tlv<'_>) -> Result<Self, TlvError> {
        too_short(t, 2)?;
        Ok(DeviceCapabilityExtension(u16::from_le_bytes([
            t.value[0], t.value[1],
        ])))
    }

    /// Writes the TLV.
    pub fn write(self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        tlv::write_tlv(w, tag::DEVICE_CAPABILITY_EXTENSION, &self.0.to_le_bytes())
    }
}

/// Writes an encapsulation TLV (Joiner or Beacon Appendix) whose value is
/// produced by `body`.
pub fn write_encapsulation(
    w: &mut Writer<'_>,
    tag: u8,
    body: impl FnOnce(&mut Writer<'_>) -> Result<(), CodecError>,
) -> Result<(), CodecError> {
    tlv::write_tlv_with(w, tag, body)
}

/// Convenience accessors over a validated [`TlvSet`] for the global TLVs.
pub trait GlobalTlvs<'a> {
    /// Supported Key Negotiation Methods, if present and well formed.
    fn key_negotiation_methods(&self) -> Option<SupportedKeyNegotiationMethods>;
    /// Router Information, if present.
    fn router_information(&self) -> Option<RouterInformation>;
    /// Fragmentation Parameters, if present.
    fn fragmentation_parameters(&self) -> Option<FragmentationParameters>;
    /// The inner TLVs of the Joiner Encapsulation, if present.
    fn joiner_encapsulation(&self) -> Option<TlvSet<'a>>;
    /// The inner TLVs of the Beacon Appendix Encapsulation, if present.
    fn beacon_appendix_encapsulation(&self) -> Option<TlvSet<'a>>;
    /// Symmetric Passphrase, if present.
    fn symmetric_passphrase(&self) -> Option<SymmetricPassphrase>;
    /// Configuration Parameters, if present.
    fn configuration_parameters(&self) -> Option<ConfigurationParameters>;
    /// Device Capability Extension, if present.
    fn device_capability_extension(&self) -> Option<DeviceCapabilityExtension>;
}

impl<'a> GlobalTlvs<'a> for TlvSet<'a> {
    fn key_negotiation_methods(&self) -> Option<SupportedKeyNegotiationMethods> {
        self.find(tag::SUPPORTED_KEY_NEGOTIATION_METHODS)
            .and_then(|t| SupportedKeyNegotiationMethods::parse(&t).ok())
    }

    fn router_information(&self) -> Option<RouterInformation> {
        self.find(tag::ROUTER_INFORMATION)
            .and_then(|t| RouterInformation::parse(&t).ok())
    }

    fn fragmentation_parameters(&self) -> Option<FragmentationParameters> {
        self.find(tag::FRAGMENTATION_PARAMETERS)
            .and_then(|t| FragmentationParameters::parse(&t).ok())
    }

    fn joiner_encapsulation(&self) -> Option<TlvSet<'a>> {
        self.find(tag::JOINER_ENCAPSULATION)
            .and_then(|t| TlvSet::validate(t.value, |_| false).ok())
    }

    fn beacon_appendix_encapsulation(&self) -> Option<TlvSet<'a>> {
        self.find(tag::BEACON_APPENDIX_ENCAPSULATION)
            .and_then(|t| TlvSet::validate(t.value, |_| false).ok())
    }

    fn symmetric_passphrase(&self) -> Option<SymmetricPassphrase> {
        self.find(tag::SYMMETRIC_PASSPHRASE)
            .and_then(|t| SymmetricPassphrase::parse(&t).ok())
    }

    fn configuration_parameters(&self) -> Option<ConfigurationParameters> {
        self.find(tag::CONFIGURATION_PARAMETERS)
            .and_then(|t| ConfigurationParameters::parse(&t).ok())
    }

    fn device_capability_extension(&self) -> Option<DeviceCapabilityExtension> {
        self.find(tag::DEVICE_CAPABILITY_EXTENSION)
            .and_then(|t| DeviceCapabilityExtension::parse(&t).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_negotiation_methods_round_trip_and_min_length() {
        let m = SupportedKeyNegotiationMethods {
            protocols: SupportedKeyNegotiationMethods::PROTO_SPEKE_CURVE25519_AES_MMO
                | SupportedKeyNegotiationMethods::PROTO_STATIC_KEY_REQUEST,
            secrets: SupportedKeyNegotiationMethods::SECRET_INSTALL_CODE,
            source: Some(ExtendedAddress(0x0102_0304_0506_0708)),
        };
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        m.write(&mut w).unwrap();
        let n = w.position();
        assert_eq!(n, 12);
        let set = TlvSet::validate(&buf[..n], |_| false).unwrap();
        assert_eq!(set.key_negotiation_methods(), Some(m));
        assert!(m.offers_key_negotiation());
        // Two-octet minimum form without source.
        let short = [65, 1, 0x02, 0x00];
        let set = TlvSet::validate(&short, |_| false).unwrap();
        let p = set.key_negotiation_methods().unwrap();
        assert_eq!(p.source, None);
        assert_eq!(p.protocols, 2);
        // One octet is malformed.
        let bad = [65, 0, 0x02];
        let set = TlvSet::validate(&bad, |_| false).unwrap();
        assert!(set.key_negotiation_methods().is_none());
    }

    #[test]
    fn fixed_size_tlvs() {
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        RouterInformation(RouterInformation::HUB_CONNECTIVITY | RouterInformation::LONG_UPTIME)
            .write(&mut w)
            .unwrap();
        FragmentationParameters {
            node: ShortAddress(0),
            options: 1,
            max_incoming_transfer_unit: 1500,
        }
        .write(&mut w)
        .unwrap();
        NextPanIdChange {
            pan_id: PanId(0xBEEF),
        }
        .write(&mut w)
        .unwrap();
        NextChannelChange {
            mask: ChannelMask(0x0000_0800),
        }
        .write(&mut w)
        .unwrap();
        ConfigurationParameters(ConfigurationParameters::LEAVE_REQUEST_ALLOWED)
            .write(&mut w)
            .unwrap();
        PanIdConflictReport { count: 3 }.write(&mut w).unwrap();
        DeviceCapabilityExtension(1).write(&mut w).unwrap();
        SymmetricPassphrase { value: [7; 16] }
            .write(&mut w)
            .unwrap();
        let n = w.position();
        let set = TlvSet::validate(&buf[..n], |_| false).unwrap();
        let ri = set.router_information().unwrap();
        assert!(ri.hub_connectivity());
        assert!(ri.long_uptime());
        assert!(!ri.preferred_parent());
        let fp = set.fragmentation_parameters().unwrap();
        assert_eq!(fp.max_incoming_transfer_unit, 1500);
        assert_eq!(fp.options, 1);
        assert_eq!(
            set.configuration_parameters(),
            Some(ConfigurationParameters(4))
        );
        assert_eq!(
            set.device_capability_extension(),
            Some(DeviceCapabilityExtension(1))
        );
        assert_eq!(set.symmetric_passphrase().unwrap().value, [7; 16]);
        assert_eq!(
            NextPanIdChange::parse(&set.find(67).unwrap())
                .unwrap()
                .pan_id,
            PanId(0xBEEF)
        );
        assert_eq!(
            NextChannelChange::parse(&set.find(68).unwrap())
                .unwrap()
                .mask
                .raw(),
            0x800
        );
        assert_eq!(
            PanIdConflictReport::parse(&set.find(66).unwrap())
                .unwrap()
                .count,
            3
        );
    }

    #[test]
    fn joiner_encapsulation_nesting() {
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        write_encapsulation(&mut w, tag::JOINER_ENCAPSULATION, |w| {
            FragmentationParameters {
                node: ShortAddress(0),
                options: 0,
                max_incoming_transfer_unit: 128,
            }
            .write(w)?;
            SupportedKeyNegotiationMethods {
                protocols: 2,
                secrets: 0,
                source: None,
            }
            .write(w)
        })
        .unwrap();
        let n = w.position();
        let set = TlvSet::validate(&buf[..n], |_| false).unwrap();
        let inner = set.joiner_encapsulation().unwrap();
        assert!(inner.fragmentation_parameters().is_some());
        assert!(
            inner
                .key_negotiation_methods()
                .unwrap()
                .offers_key_negotiation()
        );
        assert!(set.beacon_appendix_encapsulation().is_none());
    }
}
