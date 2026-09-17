//! Information elements of IEEE 802.15.4-2015 frames as Zigbee uses
//! them (R23.2 Annex D.11.1): the Enhanced Beacon Request (a Beacon
//! Request command with frame version 2 and an IE list) and the
//! Enhanced Beacon (a version 2 beacon whose beacon fields travel in an
//! IE). Only the payload IEs Zigbee defines are interpreted: the MLME
//! nested EB Filter IE (802.15.4-2020 §7.4.4.6) and the Zigbee Payload
//! IE (vendor specific, OUI `4A-19-1B`) with its Rejoin, TX Power and
//! EB Payload sub-IEs (Table D-5). Unknown IEs are skipped (D.11.1).
//!
//! Layout (Figure D-1): a header IE list holding only the HT1
//! terminator, then payload IEs, a payload termination IE and, for a
//! command frame, the command identifier.

use panweave_codec::{CodecError, Encode, Reader, Writer};
use panweave_types::{ExtendedAddress, ShortAddress};

use crate::frame::SuperframeSpec;

/// Header Termination 1 IE (element ID 0x7E, length 0): payload IEs
/// follow the header.
pub const HEADER_TERMINATION_1: [u8; 2] = 0x3F00u16.to_le_bytes();
/// Payload Termination IE (group ID 0xF, length 0).
pub const PAYLOAD_TERMINATION: u16 = 0xF800;
/// Payload IE group ID of MLME nested IEs.
pub const GROUP_MLME: u8 = 0x1;
/// Payload IE group ID of vendor specific IEs.
pub const GROUP_VENDOR: u8 = 0x2;
/// Payload IE group ID of the termination IE.
pub const GROUP_TERMINATION: u8 = 0xF;
/// The Connectivity Standards Alliance OUI carried by the Zigbee
/// Payload IE, in on-air order.
pub const ZIGBEE_OUI: [u8; 3] = [0x1B, 0x19, 0x4A];
/// MLME short sub-IE ID of the EB Filter IE.
pub const SUB_ID_EB_FILTER: u8 = 0x1E;
/// Zigbee sub-IE: Rejoin IE (Table D-5).
pub const ZIGBEE_SUB_REJOIN: u16 = 0x00;
/// Zigbee sub-IE: TX Power IE.
pub const ZIGBEE_SUB_TX_POWER: u16 = 0x01;
/// Zigbee sub-IE: EB Payload IE.
pub const ZIGBEE_SUB_EB_PAYLOAD: u16 = 0x02;
/// Beacon Request command identifier.
const BEACON_REQUEST_ID: u8 = 0x07;
/// The standard Zigbee beacon payload length (Figure D-2).
pub const EB_BEACON_PAYLOAD_LEN: usize = 15;

/// One payload IE: `length(11) | group(4) | type(1)` then the content.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PayloadIe<'a> {
    /// Group ID.
    pub group: u8,
    /// Content.
    pub content: &'a [u8],
}

/// Splits the payload IE list at the front of `bytes`: the IEs before
/// the payload termination IE and the bytes after it. Without a
/// termination IE the whole input is IEs.
pub fn split_payload_ies(bytes: &[u8]) -> Result<(&[u8], &[u8]), CodecError> {
    let mut pos = 0usize;
    while pos + 2 <= bytes.len() {
        let word = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
        if word & 0x8000 == 0 {
            return Err(CodecError::InvalidField {
                field: "payload IE type",
                value: 0,
            });
        }
        let len = usize::from(word & 0x07FF);
        let group = u8::try_from((word >> 11) & 0xF).unwrap_or(0);
        if group == GROUP_TERMINATION {
            return Ok((&bytes[..pos], &bytes[pos + 2..]));
        }
        let next = pos + 2 + len;
        if next > bytes.len() {
            return Err(CodecError::Truncated {
                needed: len,
                available: bytes.len() - pos - 2,
            });
        }
        pos = next;
    }
    if pos == bytes.len() {
        Ok((bytes, &[]))
    } else {
        Err(CodecError::Truncated {
            needed: 2,
            available: bytes.len() - pos,
        })
    }
}

/// Iterates the payload IEs of a list produced by [`split_payload_ies`].
pub fn payload_ies(list: &[u8]) -> impl Iterator<Item = PayloadIe<'_>> {
    let mut pos = 0usize;
    core::iter::from_fn(move || {
        if pos + 2 > list.len() {
            return None;
        }
        let word = u16::from_le_bytes([list[pos], list[pos + 1]]);
        let len = usize::from(word & 0x07FF);
        let group = u8::try_from((word >> 11) & 0xF).unwrap_or(0);
        let start = pos + 2;
        let end = (start + len).min(list.len());
        pos = end;
        Some(PayloadIe {
            group,
            content: &list[start..end],
        })
    })
}

fn write_payload_ie(w: &mut Writer<'_>, group: u8, content: &[u8]) -> Result<(), CodecError> {
    let len = u16::try_from(content.len()).map_err(|_| CodecError::Unrepresentable {
        field: "payload IE length",
    })?;
    if len > 0x07FF {
        return Err(CodecError::Unrepresentable {
            field: "payload IE length",
        });
    }
    w.u16_le(0x8000 | (u16::from(group & 0xF) << 11) | len)?;
    w.bytes(content)
}

/// EB Filter IE content (802.15.4-2020 §7.4.4.6, D.11.1.1): a joining
/// device sets Permit Joining On and may add the link quality and
/// percent filters; attribute IDs are never used.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EbFilter {
    /// Only PANs with joining permitted respond.
    pub permit_joining_on: bool,
    /// Only devices that received the request at this LQI or better
    /// respond.
    pub link_quality: Option<u8>,
    /// Only this percentage of devices respond.
    pub percent: Option<u8>,
}

impl EbFilter {
    /// The filter of a joining device (D.11.1.1).
    pub const JOINING: EbFilter = EbFilter {
        permit_joining_on: true,
        link_quality: None,
        percent: None,
    };

    fn parse(content: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(content);
        let control = r.u8()?;
        let link_quality = if control & 0x02 != 0 {
            Some(r.u8()?)
        } else {
            None
        };
        let percent = if control & 0x04 != 0 {
            Some(r.u8()?)
        } else {
            None
        };
        Ok(EbFilter {
            permit_joining_on: control & 0x01 != 0,
            link_quality,
            percent,
        })
    }

    fn encoded_len(self) -> usize {
        1 + usize::from(self.link_quality.is_some()) + usize::from(self.percent.is_some())
    }

    fn write(self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let control = u8::from(self.permit_joining_on)
            | (u8::from(self.link_quality.is_some()) << 1)
            | (u8::from(self.percent.is_some()) << 2);
        w.u8(control)?;
        if let Some(q) = self.link_quality {
            w.u8(q)?;
        }
        if let Some(p) = self.percent {
            w.u8(p)?;
        }
        Ok(())
    }
}

/// A Zigbee Payload nested sub-IE (Figure D-5, Table D-5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ZigbeeIe<'a> {
    /// Rejoin IE (Figure D-6).
    Rejoin {
        /// `nwkExtendedPANId` of the rejoining device.
        extended_pan_id: ExtendedAddress,
        /// Its network address.
        sender_short: ShortAddress,
    },
    /// TX Power IE (Figure D-7): the power the frame was sent at, dBm.
    TxPower(i8),
    /// EB Payload IE (Figure D-8): the standard beacon information.
    EbPayload {
        /// The Zigbee beacon payload.
        beacon_payload: &'a [u8],
        /// Superframe specification.
        superframe: SuperframeSpec,
        /// Network address of the beaconing device.
        sender_short: ShortAddress,
    },
    /// A reserved sub-ID.
    Unknown {
        /// Sub-ID.
        sub_id: u16,
        /// Content.
        content: &'a [u8],
    },
}

impl<'a> ZigbeeIe<'a> {
    fn parse(sub_id: u16, content: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(content);
        Ok(match sub_id {
            ZIGBEE_SUB_REJOIN => ZigbeeIe::Rejoin {
                extended_pan_id: ExtendedAddress(r.u64_le()?),
                sender_short: ShortAddress(r.u16_le()?),
            },
            ZIGBEE_SUB_TX_POWER => ZigbeeIe::TxPower(i8::from_le_bytes([r.u8()?])),
            ZIGBEE_SUB_EB_PAYLOAD => {
                let n = content.len().checked_sub(4).ok_or(CodecError::Truncated {
                    needed: 4,
                    available: content.len(),
                })?;
                let beacon_payload = r.bytes(n)?;
                let superframe = SuperframeSpec::from_raw(r.u16_le()?);
                let sender_short = ShortAddress(r.u16_le()?);
                ZigbeeIe::EbPayload {
                    beacon_payload,
                    superframe,
                    sender_short,
                }
            }
            _ => ZigbeeIe::Unknown { sub_id, content },
        })
    }

    fn content_len(&self) -> usize {
        match self {
            ZigbeeIe::Rejoin { .. } => 10,
            ZigbeeIe::TxPower(_) => 1,
            ZigbeeIe::EbPayload { beacon_payload, .. } => beacon_payload.len() + 4,
            ZigbeeIe::Unknown { content, .. } => content.len(),
        }
    }

    fn write(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let (sub_id, len) = (
            match self {
                ZigbeeIe::Rejoin { .. } => ZIGBEE_SUB_REJOIN,
                ZigbeeIe::TxPower(_) => ZIGBEE_SUB_TX_POWER,
                ZigbeeIe::EbPayload { .. } => ZIGBEE_SUB_EB_PAYLOAD,
                ZigbeeIe::Unknown { sub_id, .. } => *sub_id,
            },
            self.content_len(),
        );
        let len =
            u16::try_from(len)
                .ok()
                .filter(|l| *l < 64)
                .ok_or(CodecError::Unrepresentable {
                    field: "Zigbee sub-IE length",
                })?;
        w.u16_le(len | (sub_id << 6))?;
        match self {
            ZigbeeIe::Rejoin {
                extended_pan_id,
                sender_short,
            } => {
                w.u64_le(extended_pan_id.0)?;
                w.u16_le(sender_short.0)
            }
            ZigbeeIe::TxPower(p) => w.u8(p.to_le_bytes()[0]),
            ZigbeeIe::EbPayload {
                beacon_payload,
                superframe,
                sender_short,
            } => {
                w.bytes(beacon_payload)?;
                w.u16_le(superframe.to_raw())?;
                w.u16_le(sender_short.0)
            }
            ZigbeeIe::Unknown { content, .. } => w.bytes(content),
        }
    }
}

/// Iterates the Zigbee sub-IEs of a vendor specific payload IE with the
/// Zigbee OUI; `None` for any other vendor.
pub fn zigbee_ies(vendor_content: &[u8]) -> Option<impl Iterator<Item = ZigbeeIe<'_>>> {
    let rest = vendor_content.strip_prefix(&ZIGBEE_OUI)?;
    let mut pos = 0usize;
    Some(core::iter::from_fn(move || {
        if pos + 2 > rest.len() {
            return None;
        }
        let word = u16::from_le_bytes([rest[pos], rest[pos + 1]]);
        let len = usize::from(word & 0x3F);
        let sub_id = word >> 6;
        let start = pos + 2;
        let end = (start + len).min(rest.len());
        pos = end;
        ZigbeeIe::parse(sub_id, &rest[start..end]).ok()
    }))
}

fn write_zigbee_ie(w: &mut Writer<'_>, ies: &[ZigbeeIe<'_>]) -> Result<(), CodecError> {
    let len: usize = 3 + ies.iter().map(|i| 2 + i.content_len()).sum::<usize>();
    let len = u16::try_from(len).map_err(|_| CodecError::Unrepresentable {
        field: "Zigbee Payload IE length",
    })?;
    w.u16_le(0x8000 | (u16::from(GROUP_VENDOR) << 11) | len)?;
    w.bytes(&ZIGBEE_OUI)?;
    for ie in ies {
        ie.write(w)?;
    }
    Ok(())
}

/// The interpreted content of an Enhanced Beacon Request (D.11.1.1,
/// D.11.1.3): joining requests carry the EB Filter IE, rejoin requests
/// the Rejoin IE; both carry the TX Power IE when power control is used.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EnhancedBeaconRequest {
    /// EB Filter IE (joining).
    pub filter: Option<EbFilter>,
    /// Rejoin IE (rejoining).
    pub rejoin: Option<(ExtendedAddress, ShortAddress)>,
    /// TX Power IE.
    pub tx_power: Option<i8>,
}

impl EnhancedBeaconRequest {
    /// The request of a joining device.
    pub const fn joining(tx_power: Option<i8>) -> Self {
        EnhancedBeaconRequest {
            filter: Some(EbFilter::JOINING),
            rejoin: None,
            tx_power,
        }
    }

    /// The request of a rejoining device.
    pub const fn rejoining(
        extended_pan_id: ExtendedAddress,
        short: ShortAddress,
        tx_power: Option<i8>,
    ) -> Self {
        EnhancedBeaconRequest {
            filter: None,
            rejoin: Some((extended_pan_id, short)),
            tx_power,
        }
    }

    /// Parses the MAC payload of a version 2 Beacon Request command
    /// frame (payload IEs, termination, command identifier).
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let (ies, rest) = split_payload_ies(payload)?;
        if rest.first() != Some(&BEACON_REQUEST_ID) {
            return Err(CodecError::InvalidField {
                field: "MAC command",
                value: u32::from(rest.first().copied().unwrap_or(0)),
            });
        }
        let mut out = EnhancedBeaconRequest::default();
        for ie in payload_ies(ies) {
            match ie.group {
                GROUP_MLME => {
                    for sub in mlme_short_ies(ie.content) {
                        if sub.0 == SUB_ID_EB_FILTER {
                            out.filter = Some(EbFilter::parse(sub.1)?);
                        }
                    }
                }
                GROUP_VENDOR => {
                    for z in zigbee_ies(ie.content).into_iter().flatten() {
                        match z {
                            ZigbeeIe::Rejoin {
                                extended_pan_id,
                                sender_short,
                            } => out.rejoin = Some((extended_pan_id, sender_short)),
                            ZigbeeIe::TxPower(p) => out.tx_power = Some(p),
                            ZigbeeIe::EbPayload { .. } | ZigbeeIe::Unknown { .. } => {}
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(out)
    }

    /// Writes the MAC payload (payload IEs, termination and command
    /// identifier); the header carries [`HEADER_TERMINATION_1`].
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        if let Some(f) = &self.filter {
            let mut buf = [0u8; 5];
            let n = {
                let mut fw = Writer::new(&mut buf);
                fw.u16_le(
                    u16::from(SUB_ID_EB_FILTER) << 8 | u16::try_from(f.encoded_len()).unwrap_or(0),
                )?;
                f.write(&mut fw)?;
                fw.written().len()
            };
            write_payload_ie(w, GROUP_MLME, buf.get(..n).unwrap_or(&[]))?;
        }
        let mut z: heapless::Vec<ZigbeeIe<'_>, 2> = heapless::Vec::new();
        if let Some((epid, short)) = self.rejoin {
            let _ = z.push(ZigbeeIe::Rejoin {
                extended_pan_id: epid,
                sender_short: short,
            });
        }
        if let Some(p) = self.tx_power {
            let _ = z.push(ZigbeeIe::TxPower(p));
        }
        if !z.is_empty() {
            write_zigbee_ie(w, &z)?;
        }
        w.u16_le(PAYLOAD_TERMINATION)?;
        w.u8(BEACON_REQUEST_ID)
    }
}

impl Encode for EnhancedBeaconRequest {
    fn encoded_len(&self) -> usize {
        let filter = self.filter.map_or(0, |f| 4 + f.encoded_len());
        let zigbee = match (self.rejoin.is_some(), self.tx_power.is_some()) {
            (false, false) => 0,
            (r, t) => 5 + usize::from(r) * 12 + usize::from(t) * 3,
        };
        filter + zigbee + 3
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        self.write(w)
    }
}

/// Iterates MLME short sub-IEs: `length(8) | sub-id(7) | type(1)=0`.
fn mlme_short_ies(content: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut pos = 0usize;
    core::iter::from_fn(move || {
        if pos + 2 > content.len() {
            return None;
        }
        let word = u16::from_le_bytes([content[pos], content[pos + 1]]);
        if word & 0x8000 != 0 {
            // Long sub-IE: length(11) | sub-id(4); skipped.
            let len = usize::from(word & 0x07FF);
            pos = (pos + 2 + len).min(content.len());
            return Some((0xFF, &[][..]));
        }
        let len = usize::from(word & 0xFF);
        let sub_id = u8::try_from((word >> 8) & 0x7F).unwrap_or(0);
        let start = pos + 2;
        let end = (start + len).min(content.len());
        pos = end;
        Some((sub_id, &content[start..end]))
    })
}

/// The interpreted content of an Enhanced Beacon (D.11.1.2, Figure
/// D-8): the standard beacon information in the EB Payload IE and the
/// TX Power IE.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EnhancedBeacon<'a> {
    /// The Zigbee beacon payload.
    pub beacon_payload: &'a [u8],
    /// Superframe specification.
    pub superframe: SuperframeSpec,
    /// Network address of the beaconing device.
    pub sender_short: ShortAddress,
    /// TX Power IE.
    pub tx_power: Option<i8>,
}

impl<'a> EnhancedBeacon<'a> {
    /// Parses the MAC payload of a version 2 beacon frame.
    pub fn parse(payload: &'a [u8]) -> Result<Self, CodecError> {
        let (ies, _) = split_payload_ies(payload)?;
        let mut eb: Option<(&'a [u8], SuperframeSpec, ShortAddress)> = None;
        let mut tx_power = None;
        for ie in payload_ies(ies) {
            if ie.group != GROUP_VENDOR {
                continue;
            }
            for z in zigbee_ies(ie.content).into_iter().flatten() {
                match z {
                    ZigbeeIe::EbPayload {
                        beacon_payload,
                        superframe,
                        sender_short,
                    } => eb = Some((beacon_payload, superframe, sender_short)),
                    ZigbeeIe::TxPower(p) => tx_power = Some(p),
                    ZigbeeIe::Rejoin { .. } | ZigbeeIe::Unknown { .. } => {}
                }
            }
        }
        let (beacon_payload, superframe, sender_short) = eb.ok_or(CodecError::InvalidField {
            field: "EB Payload IE",
            value: 0,
        })?;
        Ok(EnhancedBeacon {
            beacon_payload,
            superframe,
            sender_short,
            tx_power,
        })
    }

    /// Writes the MAC payload (payload IEs and termination).
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let mut z: heapless::Vec<ZigbeeIe<'_>, 2> = heapless::Vec::new();
        let _ = z.push(ZigbeeIe::EbPayload {
            beacon_payload: self.beacon_payload,
            superframe: self.superframe,
            sender_short: self.sender_short,
        });
        if let Some(p) = self.tx_power {
            let _ = z.push(ZigbeeIe::TxPower(p));
        }
        write_zigbee_ie(w, &z)?;
        w.u16_le(PAYLOAD_TERMINATION)
    }
}

impl Encode for EnhancedBeacon<'_> {
    fn encoded_len(&self) -> usize {
        5 + 2 + self.beacon_payload.len() + 4 + usize::from(self.tx_power.is_some()) * 3 + 2
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        self.write(w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The payload of Figure D-1 after the MAC header and HT1.
    const FIGURE_D1: [u8; 16] = [
        0x03, 0x88, // MLME nested, length 3
        0x01, 0x1E, // EB Filter, length 1
        0x01, // Permit joining on
        0x06, 0x90, // Vendor specific, length 6
        0x1B, 0x19, 0x4A, // Zigbee OUI
        0x41, 0x00, // TX Power, length 1
        0x1B, // 27 dBm
        0x00, 0xF8, // Payload termination
        0x07, // Beacon Request
    ];

    #[test]
    fn enhanced_beacon_request_of_figure_d1() {
        let ebr = EnhancedBeaconRequest::parse(&FIGURE_D1).unwrap();
        assert_eq!(ebr.filter, Some(EbFilter::JOINING));
        assert_eq!(ebr.tx_power, Some(27));
        assert_eq!(ebr.rejoin, None);
        let mut buf = [0u8; 32];
        let n = {
            let mut w = Writer::new(&mut buf);
            EnhancedBeaconRequest::joining(Some(27))
                .write(&mut w)
                .unwrap();
            w.written().len()
        };
        assert_eq!(&buf[..n], &FIGURE_D1);
        assert_eq!(EnhancedBeaconRequest::joining(Some(27)).encoded_len(), n);
        assert_eq!(HEADER_TERMINATION_1, [0x00, 0x3F]);
    }

    #[test]
    fn rejoin_request_round_trips_and_unknown_ies_are_skipped() {
        let epid = ExtendedAddress(0x0011_2233_4455_6677);
        let req = EnhancedBeaconRequest::rejoining(epid, ShortAddress(0x1234), Some(8));
        let mut buf = [0u8; 40];
        let n = {
            let mut w = Writer::new(&mut buf);
            req.write(&mut w).unwrap();
            w.written().len()
        };
        assert_eq!(EnhancedBeaconRequest::parse(&buf[..n]).unwrap(), req);
        assert_eq!(req.encoded_len(), n);
        // Rejoin IE: length 10, sub-ID 0 → 0x000A; after the OUI.
        assert_eq!(&buf[5..7], &[0x0A, 0x00]);
        // An unknown vendor IE and an unknown MLME IE before it are
        // ignored; a link quality filter is read.
        let with_unknown = [
            0x02, 0x90, 0xAA, 0xBB, // other vendor
            0x04, 0x88, 0x02, 0x1E, 0x03, 0x40, // filter: permit + LQ 0x40
            0x00, 0xF8, 0x07,
        ];
        let ebr = EnhancedBeaconRequest::parse(&with_unknown).unwrap();
        assert_eq!(
            ebr.filter,
            Some(EbFilter {
                permit_joining_on: true,
                link_quality: Some(0x40),
                percent: None
            })
        );
        // Not a beacon request after the termination.
        assert!(EnhancedBeaconRequest::parse(&[0x00, 0xF8, 0x04]).is_err());
        // Truncated IE.
        assert!(EnhancedBeaconRequest::parse(&[0x06, 0x90, 0x1B]).is_err());
    }

    #[test]
    fn enhanced_beacon_round_trips() {
        let payload = [
            0x00, 0x22, 0x84, 1, 2, 3, 4, 5, 6, 7, 8, 0xFF, 0xFF, 0xFF, 0x00,
        ];
        let eb = EnhancedBeacon {
            beacon_payload: &payload,
            superframe: SuperframeSpec::non_beacon(true, true),
            sender_short: ShortAddress::COORDINATOR,
            tx_power: Some(-3),
        };
        let mut buf = [0u8; 48];
        let n = {
            let mut w = Writer::new(&mut buf);
            eb.write(&mut w).unwrap();
            w.written().len()
        };
        // Vendor IE length: OUI 3 + (2 + 19) + (2 + 1) = 27.
        assert_eq!(&buf[..2], &(0x9000u16 | 0x1B).to_le_bytes());
        let parsed = EnhancedBeacon::parse(&buf[..n]).unwrap();
        assert_eq!(parsed, eb);
        assert_eq!(eb.encoded_len(), n);
        assert!(parsed.superframe.association_permit);
        assert!(EnhancedBeacon::parse(&[0x00, 0xF8]).is_err());
    }
}
