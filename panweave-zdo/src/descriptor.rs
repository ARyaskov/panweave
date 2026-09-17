//! Zigbee descriptors (R23.2 §2.3.2): node descriptor (Table 2-31),
//! node power descriptor (Table 2-35) and simple descriptor (Table 2-40).
//! Complex and user descriptors are deprecated and not implemented.

use heapless::Vec;
use panweave_codec::{CodecError, Decode, Encode, Reader, Writer};
use panweave_types::{
    ClusterId, DeviceId, Endpoint, LogicalDeviceType, MacCapability, ManufacturerCode, ProfileId,
};

/// Stack compliance revision advertised in the server mask (§2.3.2.3.11.1).
pub const STACK_COMPLIANCE_REVISION: u8 = 23;

/// Maximum clusters per direction in a simple descriptor kept in RAM.
/// The wire limit is `apscMaxDescriptorSize` (64 octets), i.e. at most
/// 28 clusters in total; 16 per direction covers every published device
/// type.
pub const MAX_CLUSTERS: usize = 16;

/// Frequency band bits (Table 2-33).
pub mod frequency_band {
    /// 868–868.6 MHz.
    pub const BAND_868: u8 = 1 << 0;
    /// 902–928 MHz.
    pub const BAND_915: u8 = 1 << 2;
    /// 2400–2483.5 MHz.
    pub const BAND_2400: u8 = 1 << 3;
    /// GB Smart Energy sub-GHz bands.
    pub const BAND_GB_SUBGHZ: u8 = 1 << 4;
}

/// Server mask (Table 2-34).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServerMask(pub u16);

impl ServerMask {
    /// Bit 0: primary Trust Center.
    pub const PRIMARY_TRUST_CENTER: u16 = 1 << 0;
    /// Bit 1: backup Trust Center.
    pub const BACKUP_TRUST_CENTER: u16 = 1 << 1;
    /// Bit 5: network manager.
    pub const NETWORK_MANAGER: u16 = 1 << 5;
    /// Bits 9–15: stack compliance revision.
    const REVISION_SHIFT: u16 = 9;

    /// Builds a mask for this revision with the given server bits.
    pub const fn new(servers: u16) -> Self {
        ServerMask(
            (servers & 0x01FF) | ((STACK_COMPLIANCE_REVISION as u16) << Self::REVISION_SHIFT),
        )
    }

    /// The stack compliance revision field (0 for pre-R21 stacks).
    #[inline]
    pub const fn stack_compliance_revision(self) -> u8 {
        (self.0 >> Self::REVISION_SHIFT) as u8
    }

    /// True when the given server bit(s) are set.
    #[inline]
    pub const fn has(self, bits: u16) -> bool {
        self.0 & bits != 0
    }

    /// Server bits without the revision.
    #[inline]
    pub const fn servers(self) -> u16 {
        self.0 & 0x01FF
    }
}

/// Node descriptor (§2.3.2.3, 13 octets on the wire).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NodeDescriptor {
    /// Logical type.
    pub logical_type: LogicalDeviceType,
    /// APS fragmentation supported (meaningful with revision ≥ 23).
    pub fragmentation_supported: bool,
    /// APS flags (currently always zero).
    pub aps_flags: u8,
    /// Frequency band bits (Table 2-33).
    pub frequency_band: u8,
    /// MAC capability flags.
    pub mac_capability: MacCapability,
    /// Manufacturer code.
    pub manufacturer_code: ManufacturerCode,
    /// Maximum NSDU size (0x00–0x7f).
    pub max_buffer_size: u8,
    /// `apsMaxSizeASDU` (0x0000–0x7fff).
    pub max_incoming_transfer_size: u16,
    /// Server mask.
    pub server_mask: ServerMask,
    /// Maximum outgoing ASDU (0x0000–0x7fff).
    pub max_outgoing_transfer_size: u16,
    /// Descriptor capability field (deprecated, transmitted as zero).
    pub descriptor_capability: u8,
}

impl NodeDescriptor {
    /// Encoded size.
    pub const LEN: usize = 13;

    /// True when the peer advertises APS fragmentation (§2.3.2.3.4: the
    /// bit is only meaningful with a stack compliance revision ≥ 23).
    pub const fn supports_fragmentation(&self) -> bool {
        self.fragmentation_supported && self.server_mask.stack_compliance_revision() >= 23
    }
}

impl<'a> Decode<'a> for NodeDescriptor {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let b0 = r.u8()?;
        let logical_type = match b0 & 0x07 {
            0 => LogicalDeviceType::Coordinator,
            1 => LogicalDeviceType::Router,
            2 => LogicalDeviceType::EndDevice,
            v => {
                return Err(CodecError::InvalidField {
                    field: "logical type",
                    value: u32::from(v),
                });
            }
        };
        let fragmentation_supported = b0 & 0x20 != 0;
        let b1 = r.u8()?;
        let aps_flags = b1 & 0x07;
        let frequency_band = b1 >> 3;
        let mac_capability = MacCapability::from_raw(r.u8()?);
        let manufacturer_code = ManufacturerCode(r.u16_le()?);
        let max_buffer_size = r.u8()?;
        let max_incoming_transfer_size = r.u16_le()?;
        let server_mask = ServerMask(r.u16_le()?);
        let max_outgoing_transfer_size = r.u16_le()?;
        let descriptor_capability = r.u8()?;
        Ok(NodeDescriptor {
            logical_type,
            fragmentation_supported,
            aps_flags,
            frequency_band,
            mac_capability,
            manufacturer_code,
            max_buffer_size,
            max_incoming_transfer_size,
            server_mask,
            max_outgoing_transfer_size,
            descriptor_capability,
        })
    }
}

impl Encode for NodeDescriptor {
    fn encoded_len(&self) -> usize {
        Self::LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let lt: u8 = match self.logical_type {
            LogicalDeviceType::Coordinator => 0,
            LogicalDeviceType::Router => 1,
            LogicalDeviceType::EndDevice => 2,
        };
        w.u8(lt | (u8::from(self.fragmentation_supported) << 5))?;
        w.u8((self.aps_flags & 0x07) | ((self.frequency_band & 0x1F) << 3))?;
        w.u8(self.mac_capability.raw())?;
        w.u16_le(self.manufacturer_code.0)?;
        w.u8(self.max_buffer_size & 0x7F)?;
        w.u16_le(self.max_incoming_transfer_size & 0x7FFF)?;
        w.u16_le(self.server_mask.0)?;
        w.u16_le(self.max_outgoing_transfer_size & 0x7FFF)?;
        w.u8(self.descriptor_capability)
    }
}

/// Current power mode (Table 2-36).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PowerMode {
    /// Receiver synchronized with rx-on-when-idle.
    #[default]
    RxOnWhenIdle,
    /// Receiver on periodically.
    Periodic,
    /// Receiver on when stimulated.
    Stimulated,
    /// Reserved value.
    Reserved(u8),
}

/// Power source level (Table 2-39).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PowerLevel {
    /// Critical.
    Critical,
    /// 33 %.
    Percent33,
    /// 66 %.
    Percent66,
    /// 100 %.
    #[default]
    Percent100,
    /// Reserved value.
    Reserved(u8),
}

/// Node power descriptor (§2.3.2.4, 2 octets). Superseded by the ZCL Power
/// Configuration cluster but still mandatory on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PowerDescriptor {
    /// Current power mode.
    pub mode: PowerMode,
    /// Available power sources (Table 2-37 bits: 0 mains, 1 rechargeable,
    /// 2 disposable).
    pub available_sources: u8,
    /// Current power source (Table 2-38 bits).
    pub current_source: u8,
    /// Current source level.
    pub level: PowerLevel,
}

impl PowerDescriptor {
    /// Bit 0 of the source fields: constant (mains) power.
    pub const SOURCE_MAINS: u8 = 1 << 0;
    /// Bit 1: rechargeable battery.
    pub const SOURCE_RECHARGEABLE: u8 = 1 << 1;
    /// Bit 2: disposable battery.
    pub const SOURCE_DISPOSABLE: u8 = 1 << 2;

    /// Descriptor for a mains-powered, always-on node.
    pub const MAINS: PowerDescriptor = PowerDescriptor {
        mode: PowerMode::RxOnWhenIdle,
        available_sources: Self::SOURCE_MAINS,
        current_source: Self::SOURCE_MAINS,
        level: PowerLevel::Percent100,
    };
}

impl<'a> Decode<'a> for PowerDescriptor {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let b0 = r.u8()?;
        let b1 = r.u8()?;
        let mode = match b0 & 0x0F {
            0 => PowerMode::RxOnWhenIdle,
            1 => PowerMode::Periodic,
            2 => PowerMode::Stimulated,
            v => PowerMode::Reserved(v),
        };
        let level = match b1 >> 4 {
            0b0000 => PowerLevel::Critical,
            0b0100 => PowerLevel::Percent33,
            0b1000 => PowerLevel::Percent66,
            0b1100 => PowerLevel::Percent100,
            v => PowerLevel::Reserved(v),
        };
        Ok(PowerDescriptor {
            mode,
            available_sources: b0 >> 4,
            current_source: b1 & 0x0F,
            level,
        })
    }
}

impl Encode for PowerDescriptor {
    fn encoded_len(&self) -> usize {
        2
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let mode = match self.mode {
            PowerMode::RxOnWhenIdle => 0,
            PowerMode::Periodic => 1,
            PowerMode::Stimulated => 2,
            PowerMode::Reserved(v) => v & 0x0F,
        };
        let level = match self.level {
            PowerLevel::Critical => 0b0000,
            PowerLevel::Percent33 => 0b0100,
            PowerLevel::Percent66 => 0b1000,
            PowerLevel::Percent100 => 0b1100,
            PowerLevel::Reserved(v) => v & 0x0F,
        };
        w.u8(mode | (self.available_sources << 4))?;
        w.u8((self.current_source & 0x0F) | (level << 4))
    }
}

/// Simple descriptor (§2.3.2.5) with owned cluster lists.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SimpleDescriptor {
    /// Endpoint (1–254).
    pub endpoint: Endpoint,
    /// Application profile.
    pub profile: ProfileId,
    /// Device identifier within the profile.
    pub device: DeviceId,
    /// Device version (4 bits).
    pub device_version: u8,
    /// Input (server) clusters.
    pub input_clusters: Vec<ClusterId, MAX_CLUSTERS>,
    /// Output (client) clusters.
    pub output_clusters: Vec<ClusterId, MAX_CLUSTERS>,
}

impl SimpleDescriptor {
    /// Builds a descriptor; returns `None` when a cluster list does not
    /// fit.
    pub fn new(
        endpoint: Endpoint,
        profile: ProfileId,
        device: DeviceId,
        device_version: u8,
        input: &[ClusterId],
        output: &[ClusterId],
    ) -> Option<Self> {
        Some(SimpleDescriptor {
            endpoint,
            profile,
            device,
            device_version: device_version & 0x0F,
            input_clusters: Vec::from_slice(input).ok()?,
            output_clusters: Vec::from_slice(output).ok()?,
        })
    }

    /// True when the endpoint serves `cluster` (input list).
    pub fn has_input(&self, cluster: ClusterId) -> bool {
        self.input_clusters.contains(&cluster)
    }

    /// True when the endpoint is a client of `cluster` (output list).
    pub fn has_output(&self, cluster: ClusterId) -> bool {
        self.output_clusters.contains(&cluster)
    }
}

impl<'a> Decode<'a> for SimpleDescriptor {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let endpoint = Endpoint(r.u8()?);
        let profile = ProfileId(r.u16_le()?);
        let device = DeviceId(r.u16_le()?);
        let device_version = r.u8()? & 0x0F;
        let n_in = r.u8()?;
        let mut input_clusters = Vec::new();
        for _ in 0..n_in {
            input_clusters
                .push(ClusterId(r.u16_le()?))
                .map_err(|_| CodecError::Unsupported {
                    what: "simple descriptor cluster count",
                })?;
        }
        let n_out = r.u8()?;
        let mut output_clusters = Vec::new();
        for _ in 0..n_out {
            output_clusters
                .push(ClusterId(r.u16_le()?))
                .map_err(|_| CodecError::Unsupported {
                    what: "simple descriptor cluster count",
                })?;
        }
        Ok(SimpleDescriptor {
            endpoint,
            profile,
            device,
            device_version,
            input_clusters,
            output_clusters,
        })
    }
}

impl Encode for SimpleDescriptor {
    fn encoded_len(&self) -> usize {
        1 + 2 + 2 + 1 + 1 + 2 * self.input_clusters.len() + 1 + 2 * self.output_clusters.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.endpoint.0)?;
        w.u16_le(self.profile.0)?;
        w.u16_le(self.device.0)?;
        w.u8(self.device_version & 0x0F)?;
        #[allow(clippy::cast_possible_truncation)]
        w.u8(self.input_clusters.len() as u8)?;
        for c in &self.input_clusters {
            w.u16_le(c.0)?;
        }
        #[allow(clippy::cast_possible_truncation)]
        w.u8(self.output_clusters.len() as u8)?;
        for c in &self.output_clusters {
            w.u16_le(c.0)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_descriptor_round_trip() {
        let d = NodeDescriptor {
            logical_type: LogicalDeviceType::Router,
            fragmentation_supported: true,
            aps_flags: 0,
            frequency_band: frequency_band::BAND_2400,
            mac_capability: MacCapability::ROUTER,
            manufacturer_code: ManufacturerCode(0x1234),
            max_buffer_size: 82,
            max_incoming_transfer_size: 256,
            server_mask: ServerMask::new(ServerMask::PRIMARY_TRUST_CENTER),
            max_outgoing_transfer_size: 256,
            descriptor_capability: 0,
        };
        let mut buf = [0u8; 16];
        let n = d.encode_to_slice(&mut buf).unwrap();
        assert_eq!(n, 13);
        assert_eq!(buf[0], 0x21);
        assert_eq!(buf[1], 0x40);
        assert_eq!(buf[2], 0x8E);
        assert_eq!(&buf[3..5], &[0x34, 0x12]);
        let back = NodeDescriptor::decode_exact(&buf[..n]).unwrap();
        assert_eq!(back, d);
        assert_eq!(back.server_mask.stack_compliance_revision(), 23);
        assert!(back.supports_fragmentation());
        assert!(NodeDescriptor::decode_exact(&[0x03; 13]).is_err());
    }

    #[test]
    fn power_descriptor_round_trip() {
        let d = PowerDescriptor::MAINS;
        let mut buf = [0u8; 2];
        d.encode_to_slice(&mut buf).unwrap();
        assert_eq!(buf, [0x10, 0xC1]);
        assert_eq!(PowerDescriptor::decode_exact(&buf).unwrap(), d);
    }

    #[test]
    fn simple_descriptor_round_trip() {
        let d = SimpleDescriptor::new(
            Endpoint(1),
            ProfileId::HOME_AUTOMATION,
            DeviceId(0x0100),
            1,
            &[ClusterId(0x0000), ClusterId(0x0006)],
            &[ClusterId(0x0019)],
        )
        .unwrap();
        let mut buf = [0u8; 32];
        let n = d.encode_to_slice(&mut buf).unwrap();
        assert_eq!(n, 8 + 4 + 2);
        assert_eq!(
            &buf[..n],
            &[1, 0x04, 0x01, 0x00, 0x01, 1, 2, 0, 0, 6, 0, 1, 0x19, 0]
        );
        assert_eq!(SimpleDescriptor::decode_exact(&buf[..n]).unwrap(), d);
        assert!(d.has_input(ClusterId(6)));
        assert!(!d.has_output(ClusterId(6)));
        // Truncated cluster list.
        assert!(SimpleDescriptor::decode_exact(&buf[..n - 1]).is_err());
    }
}
