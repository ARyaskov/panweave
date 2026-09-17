//! GPDF frame format (GP Basic 1.1.2 §A.1.4): the GP stub NWK header
//! (NWK Frame Control, Extended NWK Frame Control, GPD SrcID / Endpoint,
//! security frame counter), the GP application payload (GPD CommandID and
//! payload) and the MIC, carried in an 802.15.4-2003 data frame whose MAC
//! header supplies the GPD IEEE address for ApplicationID 0b010.

use panweave_codec::{CodecError, Decode, Encode, Reader, Writer};
use panweave_mac::frame::{
    Frame as MacFrame, FrameType as MacFrameType, Header as MacHeader, MacAddress,
};
use panweave_types::{ExtendedAddress, PanId};

/// Zigbee Protocol Version carried by every GPDF (§A.1.4.1.2).
pub const PROTOCOL_VERSION: u8 = 3;
/// The reserved GPD SrcID "unspecified" (§A.1.4.1.4).
pub const SRC_ID_UNSPECIFIED: u32 = 0x0000_0000;
/// The GPD SrcID "all" (§A.1.4.1.4).
pub const SRC_ID_ALL: u32 = 0xFFFF_FFFF;
/// GPD endpoint "all endpoints" (§A.1.4.1.5).
pub const ENDPOINT_ALL: u8 = 0xff;
/// GPD endpoint "application endpoint-independent" (§A.1.4.1.5).
pub const ENDPOINT_INDEPENDENT: u8 = 0x00;
/// Length of the MIC (§A.1.4.1.8).
pub const MIC_LEN: usize = 4;
/// Largest GP stub NWK header (NWK FC, ext FC, IEEE-based endpoint or
/// SrcID, frame counter).
pub const MAX_HEADER: usize = 1 + 1 + 4 + 4;

/// Frame Type sub-field (Table 10).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FrameType {
    /// Data frame.
    Data,
    /// Maintenance frame (channel request / configuration).
    Maintenance,
}

/// ApplicationID sub-field (§A.1.4.1.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ApplicationId {
    /// 0b000: the GPD is identified by its 32-bit SrcID.
    SrcId,
    /// 0b010: the GPD is identified by its IEEE address and an endpoint.
    Ieee,
}

impl ApplicationId {
    /// Raw 3-bit value.
    pub const fn raw(self) -> u8 {
        match self {
            ApplicationId::SrcId => 0b000,
            ApplicationId::Ieee => 0b010,
        }
    }

    /// From the raw value; LPED (0b001) and reserved values are rejected.
    pub const fn from_raw(v: u8) -> Option<Self> {
        match v & 0x07 {
            0b000 => Some(ApplicationId::SrcId),
            0b010 => Some(ApplicationId::Ieee),
            _ => None,
        }
    }
}

/// SecurityLevel sub-field (Table 11).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SecurityLevel {
    /// 0b00: no security.
    #[default]
    None,
    /// 0b10: 4-octet frame counter and 4-octet MIC.
    Mic,
    /// 0b11: encryption plus frame counter and MIC.
    EncryptedMic,
}

impl SecurityLevel {
    /// Raw 2-bit value.
    pub const fn raw(self) -> u8 {
        match self {
            SecurityLevel::None => 0b00,
            SecurityLevel::Mic => 0b10,
            SecurityLevel::EncryptedMic => 0b11,
        }
    }

    /// From the raw value; the reserved 0b01 is rejected.
    pub const fn from_raw(v: u8) -> Option<Self> {
        match v & 0x03 {
            0b00 => Some(SecurityLevel::None),
            0b10 => Some(SecurityLevel::Mic),
            0b11 => Some(SecurityLevel::EncryptedMic),
            _ => None,
        }
    }

    /// True for the protected levels.
    pub const fn is_protected(self) -> bool {
        !matches!(self, SecurityLevel::None)
    }
}

/// The identity of a GPD (§A.1.4.1.4, §A.1.4.1.5).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GpdId {
    /// ApplicationID 0b000.
    SrcId(u32),
    /// ApplicationID 0b010: IEEE address and GPD endpoint.
    Ieee {
        /// IEEE address.
        address: ExtendedAddress,
        /// Endpoint (0x00 independent, 0xff all).
        endpoint: u8,
    },
}

impl GpdId {
    /// The ApplicationID this identity uses.
    pub const fn application_id(&self) -> ApplicationId {
        match self {
            GpdId::SrcId(_) => ApplicationId::SrcId,
            GpdId::Ieee { .. } => ApplicationId::Ieee,
        }
    }

    /// True for a SrcID in the valid range 0x00000001–0xfffffff8 or a
    /// non-zero, non-broadcast IEEE address (§A.1.4.1.4, §A.3.5.2.3).
    pub const fn is_valid(&self) -> bool {
        match self {
            GpdId::SrcId(s) => *s >= 0x0000_0001 && *s <= 0xFFFF_FFF8,
            GpdId::Ieee { address, .. } => address.0 != 0 && address.0 != 0xFFFF_FFFF_FFFF_FFFF,
        }
    }

    /// True for the "all GPDs" identity (SrcID 0xffffffff / IEEE all
    /// ones).
    pub const fn is_all(&self) -> bool {
        match self {
            GpdId::SrcId(s) => *s == SRC_ID_ALL,
            GpdId::Ieee { address, .. } => address.0 == 0xFFFF_FFFF_FFFF_FFFF,
        }
    }

    /// The 64-bit value that identifies the GPD for aliases and key
    /// derivation: the SrcID (zero-extended) or the IEEE address; the
    /// endpoint never takes part (§A.3.6.3.3.1, §A.3.7.1.2.2).
    pub const fn id_bits(&self) -> u64 {
        match self {
            GpdId::SrcId(s) => *s as u64,
            GpdId::Ieee { address, .. } => address.0,
        }
    }

    /// Same GPD, ignoring the endpoint of an IEEE identity.
    pub const fn same_device(&self, other: &GpdId) -> bool {
        match (self, other) {
            (GpdId::SrcId(a), GpdId::SrcId(b)) => *a == *b,
            (GpdId::Ieee { address: a, .. }, GpdId::Ieee { address: b, .. }) => a.0 == b.0,
            _ => false,
        }
    }

    /// The endpoint of an IEEE identity (`None` for SrcID).
    pub const fn endpoint(&self) -> Option<u8> {
        match self {
            GpdId::SrcId(_) => None,
            GpdId::Ieee { endpoint, .. } => Some(*endpoint),
        }
    }

    /// Writes the GPD ID field of a Green Power cluster command (4 or 8
    /// octets) followed by the Endpoint field for IEEE identities.
    pub fn write_with_endpoint(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        match self {
            GpdId::SrcId(s) => w.u32_le(*s),
            GpdId::Ieee { address, endpoint } => {
                w.u64_le(address.0)?;
                w.u8(*endpoint)
            }
        }
    }

    /// Reads the GPD ID (and Endpoint) fields for `application_id`.
    pub fn read_with_endpoint(
        r: &mut Reader<'_>,
        application_id: ApplicationId,
    ) -> Result<Self, CodecError> {
        Ok(match application_id {
            ApplicationId::SrcId => GpdId::SrcId(r.u32_le()?),
            ApplicationId::Ieee => GpdId::Ieee {
                address: ExtendedAddress(r.u64_le()?),
                endpoint: r.u8()?,
            },
        })
    }

    /// Encoded length of the GPD ID (+ Endpoint) fields.
    pub const fn encoded_len_with_endpoint(&self) -> usize {
        match self {
            GpdId::SrcId(_) => 4,
            GpdId::Ieee { .. } => 9,
        }
    }
}

/// NWK Frame Control field (Figure 6).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NwkFrameControl {
    /// Frame type.
    pub frame_type: FrameType,
    /// Auto-Commissioning: in a Data frame, the GPD does not implement
    /// the Commissioning GPDF; in a Maintenance frame, the GPD will not
    /// enter receive mode afterwards.
    pub auto_commissioning: bool,
    /// The Extended NWK Frame Control field is present.
    pub extension: bool,
}

impl NwkFrameControl {
    /// Raw octet.
    pub const fn raw(self) -> u8 {
        let ft = match self.frame_type {
            FrameType::Data => 0b00,
            FrameType::Maintenance => 0b01,
        };
        ft | (PROTOCOL_VERSION << 2)
            | if self.auto_commissioning { 0x40 } else { 0 }
            | if self.extension { 0x80 } else { 0 }
    }

    /// From the raw octet; wrong protocol versions and reserved frame
    /// types are rejected (§A.1.4.1.2).
    pub const fn from_raw(v: u8) -> Option<Self> {
        if (v >> 2) & 0x0F != PROTOCOL_VERSION {
            return None;
        }
        let frame_type = match v & 0x03 {
            0b00 => FrameType::Data,
            0b01 => FrameType::Maintenance,
            _ => return None,
        };
        Some(NwkFrameControl {
            frame_type,
            auto_commissioning: v & 0x40 != 0,
            extension: v & 0x80 != 0,
        })
    }
}

/// Extended NWK Frame Control field for ApplicationID 0b000 / 0b010
/// (Figure 8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ExtendedFrameControl {
    /// ApplicationID.
    pub application_id: ApplicationId,
    /// SecurityLevel.
    pub security_level: SecurityLevel,
    /// SecurityKey: 0 = shared key types, 1 = individual key types
    /// (Table 12).
    pub individual_key: bool,
    /// RxAfterTx.
    pub rx_after_tx: bool,
    /// Direction: 0 from the GPD, 1 from a proxy.
    pub from_proxy: bool,
}

impl ExtendedFrameControl {
    /// The value assumed when the field is absent (§A.1.4.1.3).
    pub const ABSENT: ExtendedFrameControl = ExtendedFrameControl {
        application_id: ApplicationId::SrcId,
        security_level: SecurityLevel::None,
        individual_key: false,
        rx_after_tx: false,
        from_proxy: false,
    };

    /// Raw octet.
    pub const fn raw(self) -> u8 {
        self.application_id.raw()
            | (self.security_level.raw() << 3)
            | if self.individual_key { 0x20 } else { 0 }
            | if self.rx_after_tx { 0x40 } else { 0 }
            | if self.from_proxy { 0x80 } else { 0 }
    }

    /// From the raw octet; unsupported ApplicationIDs and the reserved
    /// security level are rejected.
    pub const fn from_raw(v: u8) -> Option<Self> {
        let Some(application_id) = ApplicationId::from_raw(v) else {
            return None;
        };
        let Some(security_level) = SecurityLevel::from_raw(v >> 3) else {
            return None;
        };
        Some(ExtendedFrameControl {
            application_id,
            security_level,
            individual_key: v & 0x20 != 0,
            rx_after_tx: v & 0x40 != 0,
            from_proxy: v & 0x80 != 0,
        })
    }
}

/// Why a GPDF was rejected by the codec.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GpdfError {
    /// Not a GPDF (MAC frame type, protocol version, reserved values).
    NotGpdf,
    /// Truncated or inconsistent fields.
    Malformed,
    /// RxAfterTx and Auto-Commissioning both set (§A.1.4.1.2), or a
    /// Maintenance frame carrying security / addressing fields.
    Inconsistent,
    /// ApplicationID 0b010 without the GPD IEEE address in the MAC
    /// header.
    MissingIeee,
}

/// A parsed GPDF (§A.1.4.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Gpdf<'a> {
    /// MAC sequence number.
    pub mac_sequence: u8,
    /// NWK Frame Control.
    pub frame_control: NwkFrameControl,
    /// Extended NWK Frame Control (the assumed value when absent).
    pub extended: ExtendedFrameControl,
    /// GPD identity: `None` for Maintenance frames.
    pub gpd: Option<GpdId>,
    /// Security frame counter when the frame is protected.
    pub frame_counter: Option<u32>,
    /// GPD CommandID and payload, still encrypted for SecurityLevel 0b11.
    pub application_payload: &'a [u8],
    /// MIC when the frame is protected.
    pub mic: Option<[u8; MIC_LEN]>,
    /// The GP stub NWK header octets as authenticated by CCM*
    /// (§A.1.5.3.3): NWK FC, extended FC, SrcID or Endpoint, frame
    /// counter.
    pub header: &'a [u8],
}

impl<'a> Gpdf<'a> {
    /// Parses a received MAC frame as a GPDF (§A.1.4.1, §A.1.5.1.1).
    /// Frames from proxies (Direction = 1) are accepted by the codec and
    /// filtered by the stub.
    pub fn decode(mac: &MacFrame<'a>) -> Result<Self, GpdfError> {
        if mac.header.frame_control.frame_type() != MacFrameType::Data {
            return Err(GpdfError::NotGpdf);
        }
        let mac_sequence = mac.header.sequence.ok_or(GpdfError::NotGpdf)?;
        let mut r = Reader::new(mac.payload);
        let fc_raw = r.u8().map_err(|_| GpdfError::Malformed)?;
        let frame_control = NwkFrameControl::from_raw(fc_raw).ok_or(GpdfError::NotGpdf)?;
        let extended = if frame_control.extension {
            let raw = r.u8().map_err(|_| GpdfError::Malformed)?;
            ExtendedFrameControl::from_raw(raw).ok_or(GpdfError::NotGpdf)?
        } else {
            ExtendedFrameControl::ABSENT
        };
        if extended.rx_after_tx && frame_control.auto_commissioning {
            return Err(GpdfError::Inconsistent);
        }
        let mut gpd = None;
        match frame_control.frame_type {
            FrameType::Maintenance => {
                // §A.1.4.2.1: no addressing, no security, no extension.
                if frame_control.extension {
                    return Err(GpdfError::Inconsistent);
                }
            }
            FrameType::Data => {
                gpd = Some(match extended.application_id {
                    ApplicationId::SrcId => {
                        GpdId::SrcId(r.u32_le().map_err(|_| GpdfError::Malformed)?)
                    }
                    ApplicationId::Ieee => {
                        let endpoint = r.u8().map_err(|_| GpdfError::Malformed)?;
                        let address = match if extended.from_proxy {
                            mac.header.dst
                        } else {
                            mac.header.src
                        } {
                            MacAddress::Extended(a) => a,
                            _ => return Err(GpdfError::MissingIeee),
                        };
                        GpdId::Ieee { address, endpoint }
                    }
                });
            }
        }
        let protected = extended.security_level.is_protected();
        let frame_counter = if protected {
            Some(r.u32_le().map_err(|_| GpdfError::Malformed)?)
        } else {
            None
        };
        let header_len = r.position();
        let header = mac.payload.get(..header_len).ok_or(GpdfError::Malformed)?;
        let rest = r.take_rest();
        let (application_payload, mic) = if protected {
            if rest.len() < MIC_LEN {
                return Err(GpdfError::Malformed);
            }
            let split = rest.len() - MIC_LEN;
            let (p, m) = rest.split_at(split);
            let mut mic = [0u8; MIC_LEN];
            mic.copy_from_slice(m);
            (p, Some(mic))
        } else {
            (rest, None)
        };
        Ok(Gpdf {
            mac_sequence,
            frame_control,
            extended,
            gpd,
            frame_counter,
            application_payload,
            mic,
            header,
        })
    }

    /// GPD CommandID (first octet of the application payload; meaningful
    /// only once decrypted for SecurityLevel 0b11).
    pub fn command_id(&self) -> Option<u8> {
        self.application_payload.first().copied()
    }

    /// GPD Command payload after the CommandID.
    pub fn command_payload(&self) -> &'a [u8] {
        self.application_payload.get(1..).unwrap_or(&[])
    }
}

/// Builds the GP stub NWK header octets (§A.1.5.3.3) for a frame with
/// the given fields; returns the length written.
pub fn write_header(
    w: &mut Writer<'_>,
    frame_control: NwkFrameControl,
    extended: Option<ExtendedFrameControl>,
    gpd: Option<&GpdId>,
    frame_counter: Option<u32>,
) -> Result<(), CodecError> {
    w.u8(frame_control.raw())?;
    if let Some(e) = extended {
        w.u8(e.raw())?;
    }
    if frame_control.frame_type == FrameType::Data {
        match gpd {
            Some(GpdId::SrcId(s)) => w.u32_le(*s)?,
            Some(GpdId::Ieee { endpoint, .. }) => w.u8(*endpoint)?,
            None => return Err(CodecError::Unrepresentable { field: "gpd" }),
        }
    }
    if let Some(c) = frame_counter {
        w.u32_le(c)?;
    }
    Ok(())
}

/// Builds the MAC header of a GPDF sent to `dst` (§A.1.4.1.1): PAN
/// 0xffff, sequence `seq`, no source address for SrcID GPDs. Frames from
/// a GPD are sent with destination 0xffff / 0xffff; a frame to an IEEE
/// GPD carries the address in the destination field.
pub fn mac_header(seq: u8, dst: MacAddress, src: MacAddress) -> MacHeader<'static> {
    MacHeader::new(
        MacFrameType::Data,
        seq,
        PanId::BROADCAST,
        dst,
        PanId::BROADCAST,
        src,
    )
}

/// Encodes a complete unsecured or pre-secured GPDF payload (NWK header,
/// application payload, MIC) after the MAC header.
pub struct GpdfBuilder<'a> {
    /// NWK Frame Control.
    pub frame_control: NwkFrameControl,
    /// Extended NWK Frame Control when present.
    pub extended: Option<ExtendedFrameControl>,
    /// GPD identity for Data frames.
    pub gpd: Option<GpdId>,
    /// Security frame counter for protected frames.
    pub frame_counter: Option<u32>,
    /// Application payload (CommandID and payload).
    pub application_payload: &'a [u8],
    /// MIC for protected frames.
    pub mic: Option<[u8; MIC_LEN]>,
}

impl Encode for GpdfBuilder<'_> {
    fn encoded_len(&self) -> usize {
        1 + usize::from(self.extended.is_some())
            + match (self.frame_control.frame_type, &self.gpd) {
                (FrameType::Data, Some(GpdId::SrcId(_))) => 4,
                (FrameType::Data, Some(GpdId::Ieee { .. })) => 1,
                _ => 0,
            }
            + if self.frame_counter.is_some() { 4 } else { 0 }
            + self.application_payload.len()
            + if self.mic.is_some() { MIC_LEN } else { 0 }
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        write_header(
            w,
            self.frame_control,
            self.extended,
            self.gpd.as_ref(),
            self.frame_counter,
        )?;
        w.bytes(self.application_payload)?;
        if let Some(m) = &self.mic {
            w.bytes(m)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for NwkFrameControl {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let raw = r.u8()?;
        NwkFrameControl::from_raw(raw).ok_or(CodecError::InvalidField {
            field: "nwk frame control",
            value: u32::from(raw),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §A.1.5.4.2.1 (after the PHY length octet).
    const LEVEL2: [u8; 22] = [
        0x01, 0x08, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0x8C, 0x10, 0x21, 0x43, 0x65, 0x87, 0x02, 0x00,
        0x00, 0x00, 0x20, 0xCF, 0x78, 0x7E, 0x72,
    ];

    #[test]
    fn parses_the_level_2_test_vector() {
        let mac = MacFrame::decode_exact(&LEVEL2).unwrap();
        let g = Gpdf::decode(&mac).unwrap();
        assert_eq!(g.mac_sequence, 2);
        assert_eq!(g.frame_control.frame_type, FrameType::Data);
        assert!(g.frame_control.extension);
        assert!(!g.frame_control.auto_commissioning);
        assert_eq!(g.extended.application_id, ApplicationId::SrcId);
        assert_eq!(g.extended.security_level, SecurityLevel::Mic);
        assert!(!g.extended.individual_key);
        assert_eq!(g.gpd, Some(GpdId::SrcId(0x8765_4321)));
        assert_eq!(g.frame_counter, Some(2));
        assert_eq!(g.application_payload, &[0x20]);
        assert_eq!(g.mic, Some([0xCF, 0x78, 0x7E, 0x72]));
        assert_eq!(
            g.header,
            &[0x8c, 0x10, 0x21, 0x43, 0x65, 0x87, 0x02, 0x00, 0x00, 0x00]
        );
        // Rebuilt identically.
        let b = GpdfBuilder {
            frame_control: g.frame_control,
            extended: Some(g.extended),
            gpd: g.gpd,
            frame_counter: g.frame_counter,
            application_payload: g.application_payload,
            mic: g.mic,
        };
        let mut buf = [0u8; 32];
        let n = b.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[..n], &LEVEL2[7..]);
        assert_eq!(n, b.encoded_len());
    }

    #[test]
    fn unsecured_and_maintenance_frames() {
        // Unsecured toggle from SrcID 0x11223344, no extension.
        let payload = [0x0C, 0x44, 0x33, 0x22, 0x11, 0x22];
        let header = mac_header(
            7,
            MacAddress::Short(panweave_types::ShortAddress(0xffff)),
            MacAddress::None,
        );
        let mut buf = [0u8; 32];
        let n = MacFrame {
            header,
            payload: &payload,
        }
        .encode_to_slice(&mut buf)
        .unwrap();
        let mac = MacFrame::decode_exact(&buf[..n]).unwrap();
        let g = Gpdf::decode(&mac).unwrap();
        assert_eq!(g.extended, ExtendedFrameControl::ABSENT);
        assert_eq!(g.gpd, Some(GpdId::SrcId(0x1122_3344)));
        assert_eq!(g.command_id(), Some(0x22));
        assert!(g.mic.is_none());
        // Maintenance frame: channel request with payload.
        let payload = [0x0D, 0xE3, 0x85];
        let n = MacFrame {
            header,
            payload: &payload,
        }
        .encode_to_slice(&mut buf)
        .unwrap();
        let mac = MacFrame::decode_exact(&buf[..n]).unwrap();
        let g = Gpdf::decode(&mac).unwrap();
        assert_eq!(g.frame_control.frame_type, FrameType::Maintenance);
        assert!(g.gpd.is_none());
        assert_eq!(g.command_id(), Some(0xE3));
        assert_eq!(g.command_payload(), &[0x85]);
        // Wrong protocol version is not a GPDF; RxAfterTx + auto
        // commissioning is inconsistent.
        let bad = [0x08, 0x44, 0x33, 0x22, 0x11, 0x22];
        let n = MacFrame {
            header,
            payload: &bad,
        }
        .encode_to_slice(&mut buf)
        .unwrap();
        let mac = MacFrame::decode_exact(&buf[..n]).unwrap();
        assert_eq!(Gpdf::decode(&mac), Err(GpdfError::NotGpdf));
        let bad = [0xCC, 0x40, 0x44, 0x33, 0x22, 0x11, 0x22];
        let n = MacFrame {
            header,
            payload: &bad,
        }
        .encode_to_slice(&mut buf)
        .unwrap();
        let mac = MacFrame::decode_exact(&buf[..n]).unwrap();
        assert_eq!(Gpdf::decode(&mac), Err(GpdfError::Inconsistent));
    }

    #[test]
    fn ieee_identity_comes_from_the_mac_header() {
        let ieee = ExtendedAddress(0x00AA_BBCC_DDEE_FF11);
        let header = mac_header(
            9,
            MacAddress::Short(panweave_types::ShortAddress(0xffff)),
            MacAddress::Extended(ieee),
        );
        // Ext FC: app id 0b010, level 0, endpoint 3, command 0x21.
        let payload = [0x8C, 0x02, 0x03, 0x21];
        let mut buf = [0u8; 40];
        let n = MacFrame {
            header,
            payload: &payload,
        }
        .encode_to_slice(&mut buf)
        .unwrap();
        let mac = MacFrame::decode_exact(&buf[..n]).unwrap();
        let g = Gpdf::decode(&mac).unwrap();
        assert_eq!(
            g.gpd,
            Some(GpdId::Ieee {
                address: ieee,
                endpoint: 3
            })
        );
        assert_eq!(g.header, &[0x8C, 0x02, 0x03]);
        // Without the IEEE address the frame is rejected.
        let header = mac_header(
            9,
            MacAddress::Short(panweave_types::ShortAddress(0xffff)),
            MacAddress::None,
        );
        let n = MacFrame {
            header,
            payload: &payload,
        }
        .encode_to_slice(&mut buf)
        .unwrap();
        let mac = MacFrame::decode_exact(&buf[..n]).unwrap();
        assert_eq!(Gpdf::decode(&mac), Err(GpdfError::MissingIeee));
    }

    #[test]
    fn gpd_id_ranges() {
        assert!(!GpdId::SrcId(0).is_valid());
        assert!(GpdId::SrcId(1).is_valid());
        assert!(GpdId::SrcId(0xFFFF_FFF8).is_valid());
        assert!(!GpdId::SrcId(0xFFFF_FFF9).is_valid());
        assert!(GpdId::SrcId(SRC_ID_ALL).is_all());
        let a = GpdId::Ieee {
            address: ExtendedAddress(5),
            endpoint: 1,
        };
        let b = GpdId::Ieee {
            address: ExtendedAddress(5),
            endpoint: 2,
        };
        assert!(a.same_device(&b));
        assert_ne!(a, b);
    }
}
