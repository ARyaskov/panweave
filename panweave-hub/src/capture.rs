//! Bounded capture of the radio frames the hub sends and receives.
//!
//! The firmware hands every frame it transmits or receives to
//! [`CaptureBuffer::offer`]; while a capture is active (started by an
//! Admin session, for a bounded time) a sanitized copy of the frame goes
//! into a small queue the host reads with `ReadCapture` and writes to a
//! PCAP file. A full queue drops the newest frame and counts it — the
//! radio never waits for the host.
//!
//! What a capture is:
//!
//! * Frames at the **radio boundary**: the bytes the radio received and
//!   handed to the stack, and the bytes the stack asked the radio to
//!   send — after NWK and APS encryption, exactly as on the air, as MAC
//!   frames **without FCS** (PCAP link type 230,
//!   `LINKTYPE_IEEE802_15_4_NOFCS`). The capture never sees a decrypted
//!   payload or any stack buffer.
//! * Received frames passed the hardware address filter: traffic between
//!   other devices is not seen (the hub does not sniff).
//! * A transmitted frame is an attempt; its flags say whether an
//!   acknowledgement came back. RSSI and LQI exist for received frames.
//!
//! # Sanitization ([`CaptureMode`])
//!
//! Key material crosses the air in several forms, not all of them
//! recognizable from outside: a network key transport to a joiner (NWK
//! unsecured, APS-encrypted with a key-transport key derived from a link
//! key that may be the well-known one); a Trust Center link key transport
//! (NWK *secured*, APS-encrypted with a key derived from the joiner's
//! current link key — readable by anyone holding the network key when
//! that key is the well-known one); tunnelled transports to routers;
//! Green Power commissioning frames (which may carry a GPD key); and
//! payloads this code cannot parse. Whether a frame uses NWK security
//! therefore says nothing about whether it is safe to export.
//!
//! The default, [`CaptureMode::Sanitized`], is fail-closed: it keeps a
//! frame's *headers* and drops every payload that could carry a key —
//!
//! * MAC beacons, acknowledgements and MAC commands are kept whole (their
//!   payloads are defined by IEEE 802.15.4 and carry no Zigbee keys);
//! * MAC data frames keep the MAC header and the NWK header, including
//!   the NWK auxiliary security header (frame counter, key sequence
//!   number, source address) when present, and for an unsecured NWK
//!   command its command identifier; the NWK payload (APS frame, APS
//!   security, ZCL, ZDO) is omitted, secured or not;
//! * anything else — MAC security, IEEE 802.15.4-2015 frames, Green Power
//!   and inter-PAN frames, unknown NWK versions, malformed or truncated
//!   headers — keeps at most the MAC header, or nothing when even that
//!   cannot be parsed.
//!
//! [`CaptureMode::Metadata`] keeps only the MAC header of every frame;
//! [`CaptureMode::Raw`] keeps whole frames (explicit Admin choice, see
//! `docs/esp32c6-diagnostics.md`). A frame that lost bytes carries
//! [`flags::REDACTED`] and its original length, so a host can write a
//! PCAP record whose captured length is shorter than its original length
//! — never a fabricated frame.

use heapless::{Deque, Vec};

/// Largest 802.15.4 frame without FCS.
pub const MAX_FRAME: usize = 125;

/// Frame flags.
pub mod flags {
    /// The frame was received (else transmitted).
    pub const RX: u8 = 1 << 0;
    /// A transmitted frame requested an acknowledgement and got it.
    pub const ACKED: u8 = 1 << 1;
    /// A transmitted frame requested an acknowledgement and did not get
    /// it (or its CCA failed: the driver does not tell which).
    pub const NO_ACK: u8 = 1 << 2;
    /// Bytes after `data` were omitted (sanitization or size): the frame
    /// was [`super::CapturedFrame::original_len`] octets long.
    pub const REDACTED: u8 = 1 << 3;
    /// The driver reported a fault for this transmission.
    pub const TX_FAULT: u8 = 1 << 4;
}

/// What a capture keeps of each frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CaptureMode {
    /// The MAC header only: who talked to whom, when, with which frame
    /// type and sequence number.
    Metadata,
    /// Headers, no payload that could carry a key (the default).
    Sanitized,
    /// Whole frames as on the air. Exposes every network key transport to
    /// a joining device that used the well-known link key, and anything
    /// else such frames carry; Admin only, never the default.
    Raw,
}

impl CaptureMode {
    /// The wire code (0 is not a mode: a zeroed field never means raw).
    pub const fn code(self) -> u8 {
        match self {
            CaptureMode::Metadata => 1,
            CaptureMode::Sanitized => 2,
            CaptureMode::Raw => 3,
        }
    }

    /// The mode of a wire code.
    pub const fn from_code(c: u8) -> Option<Self> {
        match c {
            1 => Some(CaptureMode::Metadata),
            2 => Some(CaptureMode::Sanitized),
            3 => Some(CaptureMode::Raw),
            _ => None,
        }
    }

    /// A short name.
    pub const fn name(self) -> &'static str {
        match self {
            CaptureMode::Metadata => "metadata",
            CaptureMode::Sanitized => "sanitized",
            CaptureMode::Raw => "raw",
        }
    }

    /// The mode named `name`.
    pub fn parse(name: &str) -> Option<Self> {
        [
            CaptureMode::Metadata,
            CaptureMode::Sanitized,
            CaptureMode::Raw,
        ]
        .into_iter()
        .find(|m| m.name() == name)
    }
}

/// One captured frame.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CapturedFrame {
    /// Capture sequence number.
    pub seq: u32,
    /// Milliseconds since boot, modulo 2³².
    pub at_ms: u32,
    /// Channel (11–26).
    pub channel: u8,
    /// [`flags`].
    pub flags: u8,
    /// RSSI in dBm (received frames).
    pub rssi: Option<i8>,
    /// LQI (received frames).
    pub lqi: Option<u8>,
    /// Length of the frame on the air (without FCS), whatever was kept.
    pub original_len: u8,
    /// The kept prefix of the MAC frame (see [`flags::REDACTED`]).
    pub data: Vec<u8, MAX_FRAME>,
}

/// MAC frame types (IEEE 802.15.4 frame control bits 0–2).
mod mac_type {
    pub const BEACON: u16 = 0;
    pub const DATA: u16 = 1;
    pub const ACK: u16 = 2;
    pub const COMMAND: u16 = 3;
}

/// A parsed MAC header (2003 / 2006 framing).
struct MacHeader {
    len: usize,
    frame_type: u16,
    secured: bool,
}

/// The MAC header, or `None` when the frame is not a 2003/2006 frame or
/// is too short for the header its frame control announces.
fn mac_header(frame: &[u8]) -> Option<MacHeader> {
    let fc = u16::from_le_bytes([*frame.first()?, *frame.get(1)?]);
    let version = (fc >> 12) & 0x3;
    if version > 1 {
        return None;
    }
    let dst_mode = (fc >> 10) & 0x3;
    let src_mode = (fc >> 14) & 0x3;
    if dst_mode == 1 || src_mode == 1 {
        return None; // reserved addressing modes
    }
    let pan_compression = fc & (1 << 6) != 0;
    let addr = |mode: u16| match mode {
        2 => 2,
        3 => 8,
        _ => 0,
    };
    let mut n = 3;
    if dst_mode != 0 {
        n += 2 + addr(dst_mode);
    }
    if src_mode != 0 {
        if !(pan_compression && dst_mode != 0) {
            n += 2;
        }
        n += addr(src_mode);
    }
    (frame.len() >= n).then_some(MacHeader {
        len: n,
        frame_type: fc & 0x7,
        secured: fc & (1 << 3) != 0,
    })
}

/// NWK frame control bits.
mod nwk_fc {
    pub const FRAME_TYPE: u16 = 0x0003;
    pub const DATA: u16 = 0;
    pub const COMMAND: u16 = 1;
    pub const MULTICAST: u16 = 1 << 8;
    pub const SECURITY: u16 = 1 << 9;
    pub const SOURCE_ROUTE: u16 = 1 << 10;
    pub const DST_IEEE: u16 = 1 << 11;
    pub const SRC_IEEE: u16 = 1 << 12;
}

/// The length of a Zigbee PRO NWK header (protocol version 2, data or
/// command frame) including its auxiliary security header, whether it is
/// a command frame, and whether it is secured — or `None` for anything
/// else (Green Power and inter-PAN frames, other versions) and for
/// headers that run past the frame.
fn nwk_header(nwk: &[u8]) -> Option<(usize, bool, bool)> {
    let fc = u16::from_le_bytes([*nwk.first()?, *nwk.get(1)?]);
    let frame_type = fc & nwk_fc::FRAME_TYPE;
    let version = (fc >> 2) & 0xf;
    if version != 2 || !(frame_type == nwk_fc::DATA || frame_type == nwk_fc::COMMAND) {
        return None;
    }
    // Frame control, destination, source, radius, sequence number.
    let mut n: usize = 8;
    if fc & nwk_fc::DST_IEEE != 0 {
        n += 8;
    }
    if fc & nwk_fc::SRC_IEEE != 0 {
        n += 8;
    }
    if fc & nwk_fc::MULTICAST != 0 {
        n += 1;
    }
    if fc & nwk_fc::SOURCE_ROUTE != 0 {
        let relays = usize::from(*nwk.get(n)?);
        n += 2 + 2 * relays;
    }
    let secured = fc & nwk_fc::SECURITY != 0;
    if secured {
        let sc = *nwk.get(n)?;
        // Security control, frame counter; extended nonce: source
        // address; key identifier 1 (network key): key sequence number.
        n += 5;
        if sc & (1 << 5) != 0 {
            n += 8;
        }
        if (sc >> 3) & 0x3 == 1 {
            n += 1;
        }
    }
    (nwk.len() >= n).then_some((n, frame_type == nwk_fc::COMMAND, secured))
}

/// How many leading octets of `frame` `mode` keeps.
pub fn kept_len(frame: &[u8], mode: CaptureMode) -> usize {
    if mode == CaptureMode::Raw {
        return frame.len();
    }
    let Some(mac) = mac_header(frame) else {
        return 0;
    };
    if mode == CaptureMode::Metadata || mac.secured {
        return mac.len;
    }
    match mac.frame_type {
        mac_type::BEACON | mac_type::ACK | mac_type::COMMAND => frame.len(),
        mac_type::DATA => match frame.get(mac.len..).and_then(nwk_header) {
            Some((n, command, secured)) => {
                // An unsecured NWK command: keep its identifier.
                let id = usize::from(command && !secured);
                (mac.len + n + id).min(frame.len())
            }
            None => mac.len,
        },
        _ => mac.len,
    }
}

/// Capture state and queue of `N` frames.
#[derive(Debug)]
pub struct CaptureBuffer<const N: usize> {
    frames: Deque<CapturedFrame, N>,
    until_ms: Option<u64>,
    mode: CaptureMode,
    next_seq: u32,
    dropped: u32,
    /// Why the last capture ended: 0 request, 1 time limit.
    stopped_by_limit: bool,
}

impl<const N: usize> Default for CaptureBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> CaptureBuffer<N> {
    /// Stopped and empty.
    pub const fn new() -> Self {
        CaptureBuffer {
            frames: Deque::new(),
            until_ms: None,
            mode: CaptureMode::Sanitized,
            next_seq: 0,
            dropped: 0,
            stopped_by_limit: false,
        }
    }

    /// Starts capturing until `until_ms` (uptime): clears frames and
    /// counters left from a previous capture.
    pub fn start(&mut self, until_ms: u64, mode: CaptureMode) {
        self.frames.clear();
        self.until_ms = Some(until_ms);
        self.mode = mode;
        self.dropped = 0;
        self.stopped_by_limit = false;
    }

    /// Stops capturing; captured frames stay readable until taken,
    /// [`Self::discard`]ed or replaced by the next capture. Nothing is
    /// ever written to flash.
    pub fn stop(&mut self) {
        self.until_ms = None;
    }

    /// Discards every queued frame.
    pub fn discard(&mut self) {
        self.frames.clear();
    }

    /// Whether a capture is running at `now_ms`; ends one past its limit
    /// (returns `true` once when that happens, through `expired`).
    pub fn poll(&mut self, now_ms: u64) -> bool {
        if self.until_ms.is_some_and(|t| now_ms >= t) {
            self.until_ms = None;
            self.stopped_by_limit = true;
            return true;
        }
        false
    }

    /// Whether frames are being captured.
    pub const fn is_active(&self) -> bool {
        self.until_ms.is_some()
    }

    /// When the running capture ends.
    pub const fn until_ms(&self) -> Option<u64> {
        self.until_ms
    }

    /// What the capture keeps of each frame.
    pub const fn mode(&self) -> CaptureMode {
        self.mode
    }

    /// Frames dropped because the queue was full.
    pub const fn dropped(&self) -> u32 {
        self.dropped
    }

    /// Frames waiting to be read.
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Whether no frame is waiting.
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Whether the last capture ended by its time limit.
    pub const fn stopped_by_limit(&self) -> bool {
        self.stopped_by_limit
    }

    /// The sequence number the next frame gets.
    pub const fn next_seq(&self) -> u32 {
        self.next_seq
    }

    /// Offers a frame; a sanitized copy is queued when a capture runs.
    /// Cheap when none does: one comparison.
    pub fn offer(
        &mut self,
        now_ms: u64,
        channel: u8,
        frame: &[u8],
        frame_flags: u8,
        rssi: Option<i8>,
        lqi: Option<u8>,
    ) {
        if self.until_ms.is_none() {
            return;
        }
        if self.frames.is_full() {
            self.dropped = self.dropped.wrapping_add(1);
            return;
        }
        let keep = kept_len(frame, self.mode).min(MAX_FRAME);
        let mut f = frame_flags & !flags::REDACTED;
        if keep < frame.len() {
            f |= flags::REDACTED;
        }
        let captured = CapturedFrame {
            seq: self.next_seq,
            at_ms: u32::try_from(now_ms & u64::from(u32::MAX)).unwrap_or(0),
            channel,
            flags: f,
            rssi,
            lqi,
            original_len: u8::try_from(frame.len()).unwrap_or(u8::MAX),
            data: Vec::from_slice(frame.get(..keep).unwrap_or(&[])).unwrap_or_default(),
        };
        self.next_seq = self.next_seq.wrapping_add(1);
        let _ = self.frames.push_back(captured);
    }

    /// Moves up to `limit` frames (and `out`'s capacity) out of the
    /// queue; frames are delivered once.
    pub fn take<const M: usize>(&mut self, limit: usize, out: &mut Vec<CapturedFrame, M>) {
        while !out.is_full() && out.len() < limit {
            match self.frames.pop_front() {
                Some(f) => {
                    let _ = out.push(f);
                }
                None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MAC data, PAN ID compression, short addresses (9 octets).
    const MAC: [u8; 9] = [0x41, 0x88, 0x01, 0x34, 0x12, 0x00, 0x00, 0x01, 0x00];
    /// A synthetic secret that must never be exported by default.
    const SECRET: [u8; 16] = [0x5E; 16];

    fn frame(nwk: &[u8], payload: &[u8]) -> std::vec::Vec<u8> {
        let mut f = MAC.to_vec();
        f.extend_from_slice(nwk);
        f.extend_from_slice(payload);
        f
    }

    /// NWK data, version 2, the given extra frame-control bits; base
    /// header only.
    fn nwk(fc_extra: u16) -> std::vec::Vec<u8> {
        let fc: u16 = 0x0008 | fc_extra;
        let mut n = fc.to_le_bytes().to_vec();
        n.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x1e, 0x42]);
        n
    }

    /// The NWK auxiliary header Zigbee uses: level 5 (patched to 0 on
    /// the air), key identifier 1, extended nonce.
    fn aux() -> std::vec::Vec<u8> {
        let mut a = vec![0x28, 0x10, 0x00, 0x00, 0x00];
        a.extend_from_slice(&0x00aa_bbcc_ddee_ff00u64.to_le_bytes());
        a.push(0x00);
        a
    }

    fn contains_secret(data: &[u8]) -> bool {
        data.windows(SECRET.len()).any(|w| w == SECRET)
    }

    #[test]
    fn an_unsecured_key_transport_keeps_only_headers() {
        // APS command frame (Transport Key) carrying a key in clear.
        let mut aps = vec![0x21, 0x05, 0x05, 0x01];
        aps.extend_from_slice(&SECRET);
        let f = frame(&nwk(0), &aps);
        assert_eq!(kept_len(&f, CaptureMode::Sanitized), MAC.len() + 8);
        assert_eq!(kept_len(&f, CaptureMode::Metadata), MAC.len());
        assert_eq!(kept_len(&f, CaptureMode::Raw), f.len());
    }

    #[test]
    fn nwk_secured_frames_keep_their_security_header_not_their_payload() {
        let mut n = nwk(nwk_fc::SECURITY | nwk_fc::SRC_IEEE);
        n.extend_from_slice(&0x0011_2233_4455_6677u64.to_le_bytes());
        n.extend_from_slice(&aux());
        // An encrypted TCLK transport looks like any secured frame.
        let f = frame(&n, &SECRET);
        assert_eq!(kept_len(&f, CaptureMode::Sanitized), MAC.len() + n.len());
        assert!(!contains_secret(&f[..kept_len(&f, CaptureMode::Sanitized)]));
    }

    #[test]
    fn source_routes_multicast_and_commands_are_parsed() {
        let mut n = nwk(nwk_fc::SOURCE_ROUTE | nwk_fc::MULTICAST | nwk_fc::DST_IEEE);
        n.extend_from_slice(&[0u8; 8]); // destination IEEE
        n.push(0x01); // multicast control
        n.extend_from_slice(&[2, 0, 0x34, 0x12, 0x78, 0x56]); // 2 relays
        let f = frame(&n, &SECRET);
        assert_eq!(kept_len(&f, CaptureMode::Sanitized), MAC.len() + n.len());
        // An unsecured NWK command (a rejoin request): its identifier
        // stays, its payload goes.
        let mut cmd = nwk(0);
        cmd[0] |= 0x01;
        let f = frame(&cmd, &[0x06, 0x8e]);
        assert_eq!(kept_len(&f, CaptureMode::Sanitized), MAC.len() + 9);
    }

    #[test]
    fn unexpected_and_malformed_frames_fail_closed() {
        // Green Power (NWK protocol version 3) may carry a GPD key.
        let mut gp = vec![0x8c, 0x30];
        gp.extend_from_slice(&SECRET);
        assert_eq!(
            kept_len(&frame(&gp, &[]), CaptureMode::Sanitized),
            MAC.len()
        );
        // Inter-PAN.
        let mut ip = nwk(0);
        ip[0] |= 0x03;
        assert_eq!(
            kept_len(&frame(&ip, &SECRET), CaptureMode::Sanitized),
            MAC.len()
        );
        // An auxiliary header cut short: MAC header only.
        let mut n = nwk(nwk_fc::SECURITY);
        n.extend_from_slice(&[0x28, 0x10]);
        assert_eq!(kept_len(&frame(&n, &[]), CaptureMode::Sanitized), MAC.len());
        // A source route announcing more relays than the frame holds.
        let mut sr = nwk(nwk_fc::SOURCE_ROUTE);
        sr.extend_from_slice(&[40, 0]);
        assert_eq!(
            kept_len(&frame(&sr, &SECRET), CaptureMode::Sanitized),
            MAC.len()
        );
        // MAC security, 802.15.4-2015 framing, reserved modes, garbage.
        let mut mac_sec = frame(&nwk(0), &SECRET);
        mac_sec[0] |= 0x08;
        assert_eq!(kept_len(&mac_sec, CaptureMode::Sanitized), MAC.len());
        let mut v2015 = frame(&nwk(0), &SECRET);
        v2015[1] |= 0x20;
        assert_eq!(kept_len(&v2015, CaptureMode::Sanitized), 0);
        assert_eq!(kept_len(&[0x41], CaptureMode::Sanitized), 0);
        assert_eq!(kept_len(&[], CaptureMode::Sanitized), 0);
        assert_eq!(kept_len(&MAC[..5], CaptureMode::Sanitized), 0);
        // Unknown MAC frame types.
        let mut odd = frame(&nwk(0), &SECRET);
        odd[0] = (odd[0] & !0x07) | 0x05;
        assert_eq!(kept_len(&odd, CaptureMode::Sanitized), MAC.len());
    }

    #[test]
    fn mac_beacons_acks_and_commands_are_kept_whole() {
        let beacon_request = [0x03, 0x08, 0x05, 0xff, 0xff, 0xff, 0xff, 0x07];
        assert_eq!(kept_len(&beacon_request, CaptureMode::Sanitized), 8);
        assert_eq!(kept_len(&beacon_request, CaptureMode::Metadata), 7);
        let ack = [0x02, 0x00, 0x07];
        assert_eq!(kept_len(&ack, CaptureMode::Sanitized), 3);
    }

    #[test]
    fn the_buffer_records_original_lengths_and_never_leaks_by_default() {
        let mut aps = vec![0x21, 0x05];
        aps.extend_from_slice(&SECRET);
        let f = frame(&nwk(0), &aps);
        let mut buf: CaptureBuffer<4> = CaptureBuffer::new();
        assert_eq!(buf.mode(), CaptureMode::Sanitized);
        buf.start(1000, CaptureMode::Sanitized);
        buf.offer(10, 11, &f, flags::ACKED, None, None);
        // Oversized input: capped, flagged, original length kept.
        let big = [0x02u8; 200];
        buf.offer(11, 11, &big, flags::RX, Some(-60), Some(180));
        let mut out: Vec<CapturedFrame, 4> = Vec::new();
        buf.take(usize::MAX, &mut out);
        assert_eq!(out[0].data.len(), MAC.len() + 8);
        assert_eq!(usize::from(out[0].original_len), f.len());
        assert_eq!(out[0].flags, flags::ACKED | flags::REDACTED);
        assert!(!contains_secret(&out[0].data));
        assert_eq!(out[1].original_len, 200);
        assert!(out[1].data.len() <= MAX_FRAME);
        assert_ne!(out[1].flags & flags::REDACTED, 0);
        // Raw: the frame as sent, an explicit choice.
        buf.start(1000, CaptureMode::Raw);
        buf.offer(12, 11, &f, 0, None, None);
        out.clear();
        buf.take(usize::MAX, &mut out);
        assert_eq!(out[0].data.as_slice(), f.as_slice());
        assert_eq!(out[0].flags & flags::REDACTED, 0);
        assert_eq!(CaptureMode::from_code(0), None, "zero is never raw");
        assert_eq!(CaptureMode::parse("raw"), Some(CaptureMode::Raw));
    }

    #[test]
    fn the_queue_is_bounded_and_captures_are_time_limited() {
        let mut buf: CaptureBuffer<2> = CaptureBuffer::new();
        buf.offer(0, 11, &[1, 2, 3], 0, None, None);
        assert!(buf.is_empty(), "nothing captured while stopped");
        buf.start(100, CaptureMode::Sanitized);
        for i in 0..5u8 {
            buf.offer(u64::from(i), 11, &[i], flags::RX, None, None);
        }
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.dropped(), 3);
        assert!(!buf.poll(99));
        assert!(buf.poll(100));
        assert!(!buf.is_active());
        assert!(buf.stopped_by_limit());
        buf.offer(101, 11, &[9], 0, None, None);
        let mut out: Vec<CapturedFrame, 8> = Vec::new();
        buf.take(usize::MAX, &mut out);
        assert_eq!(out.len(), 2, "frames stay readable after the stop");
        assert_eq!(out[0].seq, 0);
        // A restart clears the counters; discard empties the queue.
        buf.start(200, CaptureMode::Metadata);
        assert_eq!(buf.dropped(), 0);
        buf.offer(150, 11, &[0x02, 0x00, 0x07], 0, None, None);
        buf.discard();
        assert!(buf.is_empty());
        buf.stop();
        assert!(!buf.stopped_by_limit());
    }
}
