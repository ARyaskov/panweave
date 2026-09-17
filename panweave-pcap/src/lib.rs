//! PCAP export for captured or simulated 802.15.4 frames, and a Zigbee
//! frame dissector for human-readable traces (host-side tooling).
//!
//! Files use the classic libpcap format with link type
//! `LINKTYPE_IEEE802_15_4_NOFCS` (230), which Wireshark decodes with its
//! Zigbee dissectors when given the network key.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )
)]

use std::io::{self, Write};

use panweave_codec::Decode;
use panweave_mac::frame::{Frame as MacFrame, FrameType as MacFrameType};
use panweave_nwk::frame::{FrameType as NwkFrameType, Header as NwkHeader};

/// `LINKTYPE_IEEE802_15_4_NOFCS`.
pub const LINKTYPE_IEEE802_15_4_NOFCS: u32 = 230;

/// Writes classic pcap files.
pub struct PcapWriter<W: Write> {
    out: W,
    packets: u64,
}

impl<W: Write> PcapWriter<W> {
    /// Writes the global header (microsecond timestamps, snap length
    /// 256).
    pub fn new(mut out: W) -> io::Result<Self> {
        out.write_all(&0xA1B2_C3D4u32.to_le_bytes())?;
        out.write_all(&2u16.to_le_bytes())?;
        out.write_all(&4u16.to_le_bytes())?;
        out.write_all(&0i32.to_le_bytes())?;
        out.write_all(&0u32.to_le_bytes())?;
        out.write_all(&256u32.to_le_bytes())?;
        out.write_all(&LINKTYPE_IEEE802_15_4_NOFCS.to_le_bytes())?;
        Ok(PcapWriter { out, packets: 0 })
    }

    /// Appends a frame (without FCS) captured at `timestamp_us`.
    pub fn write_frame(&mut self, timestamp_us: u64, frame: &[u8]) -> io::Result<()> {
        let secs = u32::try_from(timestamp_us / 1_000_000).unwrap_or(u32::MAX);
        let usecs = u32::try_from(timestamp_us % 1_000_000).unwrap_or(0);
        let len = u32::try_from(frame.len()).unwrap_or(u32::MAX);
        self.out.write_all(&secs.to_le_bytes())?;
        self.out.write_all(&usecs.to_le_bytes())?;
        self.out.write_all(&len.to_le_bytes())?;
        self.out.write_all(&len.to_le_bytes())?;
        self.out.write_all(frame)?;
        self.packets += 1;
        Ok(())
    }

    /// Number of packets written.
    pub const fn packets(&self) -> u64 {
        self.packets
    }

    /// Flushes and returns the writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.out.flush()?;
        Ok(self.out)
    }
}

/// One-line summary of a frame for traces (MAC and NWK headers only; no
/// decryption).
pub fn summarize(frame: &[u8]) -> String {
    let Ok(mac) = MacFrame::decode_exact(frame) else {
        return format!("malformed ({} octets)", frame.len());
    };
    let h = &mac.header;
    let kind = match h.frame_control.frame_type() {
        MacFrameType::Beacon => "MAC beacon",
        MacFrameType::Data => "MAC data",
        MacFrameType::Ack => "MAC ack",
        MacFrameType::Command => "MAC cmd",
        MacFrameType::Other(_) => "MAC other",
    };
    let mut s = format!(
        "{kind} seq={} {:?} -> {:?}",
        h.sequence.unwrap_or(0),
        h.src,
        h.dst
    );
    if h.frame_control.frame_type() == MacFrameType::Data
        && let Ok((nwk, n)) = NwkHeader::decode_prefix(mac.payload)
    {
        let t = match nwk.frame_control.frame_type() {
            NwkFrameType::Data => "NWK data",
            NwkFrameType::Command => "NWK cmd",
            NwkFrameType::InterPan => "NWK inter-PAN",
            NwkFrameType::Reserved => "NWK reserved",
        };
        use std::fmt::Write as _;
        let _ = write!(
            s,
            " | {t} {} -> {} radius={} seq={} secured={} payload={}B",
            nwk.src,
            nwk.dst,
            nwk.radius,
            nwk.sequence,
            nwk.frame_control.security(),
            mac.payload.len().saturating_sub(n)
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_global_and_packet_headers() {
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        w.write_frame(1_500_000, &[0x02, 0x00, 0x05]).unwrap();
        assert_eq!(w.packets(), 1);
        let bytes = w.finish().unwrap();
        assert_eq!(bytes.len(), 24 + 16 + 3);
        assert_eq!(&bytes[..4], &0xA1B2_C3D4u32.to_le_bytes());
        assert_eq!(&bytes[20..24], &230u32.to_le_bytes());
        assert_eq!(&bytes[24..28], &1u32.to_le_bytes());
        assert_eq!(&bytes[28..32], &500_000u32.to_le_bytes());
        assert_eq!(&bytes[40..], &[0x02, 0x00, 0x05]);
    }

    #[test]
    fn summary_of_ack_and_malformed() {
        assert!(summarize(&[0x02, 0x00, 0x05]).starts_with("MAC ack seq=5"));
        assert!(summarize(&[]).starts_with("malformed"));
    }
}
