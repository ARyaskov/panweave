//! The gpTxQueue of a GP infrastructure device (GP Basic 1.1.2
//! §A.1.5.2.1.1, §A.1.5.2.2): GPDFs waiting for the GPD they are meant
//! for to open its receive window (a frame with RxAfterTx, or a Channel
//! Request for Maintenance frames), transmitted gpTxOffset after that
//! frame. Shared by the proxy (filled by GP Response) and the sink
//! (filled by its own commissioning replies).

use heapless::Vec;
use panweave_codec::Encode;
use panweave_mac::frame::MacAddress;
use panweave_types::ShortAddress;
use panweave_types::time::{Duration, Instant};

use crate::gpdf::{
    ExtendedFrameControl, FrameType, GpdId, GpdfBuilder, NwkFrameControl, SecurityLevel,
};

/// gpTxOffset (§A.1.5.2.1.2): the GPDF answering a frame with RxAfterTx
/// is transmitted this long after the triggering frame.
pub const GP_TX_OFFSET: Duration = Duration::from_millis(20);
/// Largest GPDF (NWK header and payload) an infrastructure device
/// transmits (§A.3.6.1.5.1 plus the header).
pub const MAX_GPDF: usize = 80;

/// A GPDF to transmit to a GPD.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GpdfTx {
    /// Earliest transmission time (gpTxOffset after the trigger).
    pub not_before: Instant,
    /// MAC destination (0xffff or the GPD IEEE address).
    pub dst: MacAddress,
    /// Channel to transmit on (`None`: the operational channel).
    pub channel: Option<u8>,
    /// NWK header and application payload.
    pub frame: Vec<u8, MAX_GPDF>,
}

/// One gpTxQueue entry.
#[derive(Clone, Debug)]
pub struct TxEntry {
    /// The GPD the frame is for (`SrcId(0)` for Maintenance frames).
    pub gpd: GpdId,
    /// Transmit on endpoint match (IEEE GPDs).
    pub endpoint_match: bool,
    /// MAC destination.
    pub dst: MacAddress,
    /// Channel to transmit on (`None`: the operational channel).
    pub channel: Option<u8>,
    /// The frame.
    pub frame: Vec<u8, MAX_GPDF>,
}

impl TxEntry {
    /// True when a frame from `gpd` opens the window for this entry
    /// (§A.3.3.5.4: exact endpoint when requested, else the device).
    pub fn answers(&self, gpd: &GpdId) -> bool {
        if self.endpoint_match {
            self.gpd == *gpd
        } else {
            self.gpd.same_device(gpd)
        }
    }
}

/// The queue: one pending frame per GPD (§A.1.5.2.1.1).
#[derive(Clone, Debug)]
pub struct TxQueue<const N: usize> {
    entries: Vec<TxEntry, N>,
}

impl<const N: usize> Default for TxQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> TxQueue<N> {
    /// Empty queue.
    pub const fn new() -> Self {
        TxQueue {
            entries: Vec::new(),
        }
    }

    /// True when nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drops every entry.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Drops the entries for `gpd` (any endpoint).
    pub fn remove(&mut self, gpd: &GpdId) {
        self.entries.retain(|e| !e.gpd.same_device(gpd));
    }

    /// Stores `entry`, replacing an earlier one for the same GPD; the
    /// oldest entry makes room when the queue is full.
    pub fn put(&mut self, entry: TxEntry) {
        self.remove(&entry.gpd);
        if let Err(e) = self.entries.push(entry) {
            self.entries.remove(0);
            let _ = self.entries.push(e);
        }
    }

    /// Takes the entry a frame from `gpd` opens the window for.
    pub fn take(&mut self, gpd: &GpdId) -> Option<TxEntry> {
        let i = self.entries.iter().position(|e| e.answers(gpd))?;
        Some(self.entries.swap_remove(i))
    }

    /// The transmission of `entry` gpTxOffset after `now`.
    pub fn transmission(entry: TxEntry, now: Instant) -> GpdfTx {
        GpdfTx {
            not_before: now + GP_TX_OFFSET,
            dst: entry.dst,
            channel: entry.channel,
            frame: entry.frame,
        }
    }
}

/// The MAC destination of a frame to `gpd` (§A.1.4.1.1).
pub fn destination_of(gpd: &GpdId) -> MacAddress {
    match gpd {
        GpdId::SrcId(_) => MacAddress::Short(ShortAddress::BROADCAST_ALL),
        GpdId::Ieee { address, .. } => MacAddress::Extended(*address),
    }
}

/// Builds an unprotected Data GPDF from an infrastructure device to
/// `gpd` (Direction = 1, no RxAfterTx) carrying `application_payload`
/// (CommandID and payload).
pub fn build_data_gpdf(gpd: &GpdId, application_payload: &[u8]) -> Option<Vec<u8, MAX_GPDF>> {
    let builder = GpdfBuilder {
        frame_control: NwkFrameControl {
            frame_type: FrameType::Data,
            auto_commissioning: false,
            extension: true,
        },
        extended: Some(ExtendedFrameControl {
            application_id: gpd.application_id(),
            security_level: SecurityLevel::None,
            individual_key: false,
            rx_after_tx: false,
            from_proxy: true,
        }),
        gpd: Some(*gpd),
        frame_counter: None,
        application_payload,
        mic: None,
    };
    encode(&builder)
}

/// Builds a Maintenance GPDF (no addressing, no security) carrying
/// `application_payload`.
pub fn build_maintenance_gpdf(application_payload: &[u8]) -> Option<Vec<u8, MAX_GPDF>> {
    let builder = GpdfBuilder {
        frame_control: NwkFrameControl {
            frame_type: FrameType::Maintenance,
            auto_commissioning: false,
            extension: false,
        },
        extended: None,
        gpd: None,
        frame_counter: None,
        application_payload,
        mic: None,
    };
    encode(&builder)
}

fn encode(builder: &GpdfBuilder<'_>) -> Option<Vec<u8, MAX_GPDF>> {
    let mut frame: Vec<u8, MAX_GPDF> = Vec::new();
    frame.resize(builder.encoded_len(), 0).ok()?;
    builder.encode_to_slice(&mut frame).ok()?;
    Some(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_types::ExtendedAddress;

    #[test]
    fn one_entry_per_gpd_and_endpoint_matching() {
        let mut q: TxQueue<2> = TxQueue::new();
        let ieee = ExtendedAddress(0x0102_0304_0506_0708);
        let ep1 = GpdId::Ieee {
            address: ieee,
            endpoint: 1,
        };
        let ep2 = GpdId::Ieee {
            address: ieee,
            endpoint: 2,
        };
        q.put(TxEntry {
            gpd: ep1,
            endpoint_match: true,
            dst: destination_of(&ep1),
            channel: None,
            frame: build_data_gpdf(&ep1, &[0xF0, 0x00]).unwrap(),
        });
        // A frame from another endpoint of the same device does not open
        // the window when an exact match was requested.
        assert!(q.take(&ep2).is_none());
        let e = q.take(&ep1).unwrap();
        assert_eq!(e.dst, MacAddress::Extended(ieee));
        // NWK FC 0x8C, extended: ApplicationID 0b010 | direction.
        assert_eq!(&e.frame[..3], &[0x8C, 0x82, 0x01]);
        assert!(q.is_empty());
        // Without the exact-match request any endpoint does; the newest
        // entry for a device replaces the older one.
        q.put(TxEntry {
            gpd: ep1,
            endpoint_match: false,
            dst: destination_of(&ep1),
            channel: Some(15),
            frame: build_data_gpdf(&ep1, &[0xF0]).unwrap(),
        });
        q.put(TxEntry {
            gpd: ep1,
            endpoint_match: false,
            dst: destination_of(&ep1),
            channel: Some(20),
            frame: build_data_gpdf(&ep1, &[0xF0]).unwrap(),
        });
        let e = q.take(&ep2).unwrap();
        assert_eq!(e.channel, Some(20));
        assert!(q.is_empty());
        let m = build_maintenance_gpdf(&[0xF3, 0x14]).unwrap();
        assert_eq!(m.as_slice(), &[0x0D, 0xF3, 0x14]);
        let tx = TxQueue::<2>::transmission(
            TxEntry {
                gpd: GpdId::SrcId(0),
                endpoint_match: false,
                dst: MacAddress::Short(ShortAddress::BROADCAST_ALL),
                channel: None,
                frame: m,
            },
            Instant::from_millis(1000),
        );
        assert_eq!(tx.not_before, Instant::from_millis(1020));
    }
}
