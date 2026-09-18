//! Partition cluster (ZCL8 §9.6, cluster 0x0016): a large frame of a
//! registered cluster is cut into `PartitionedFrameSize` blocks carried
//! by TransferPartitionedFrame commands, acknowledged in groups of
//! `NumberOfACKFrame` with MultipleACK commands that list the blocks
//! still missing; a handshake (Read / WriteHandshakeParam) tunes the
//! parameters per transaction. [`Sender`] and [`Receiver`] are sans-I/O
//! state machines over the codecs: the caller sends what they hand out
//! and feeds them what arrives, with the time.
//!
//! Interpretation (§9.6.3.3.1, §9.6.3.4.1): blocks are numbered from 0;
//! the first block's PartitionIndicator carries the overall number of
//! blocks and every other block its index, NACKIds are block indices.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{ClusterId, CommandId, Duration, Instant};

use crate::attribute::{Access, AttributeDef};
use crate::cluster::{ClusterDef, ClusterInstance, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0016);

/// `MaximumIncomingTransferSize` (uint16, multiples of
/// `PartitionedFrameSize`).
pub const MAXIMUM_INCOMING_TRANSFER_SIZE: AttributeDef =
    AttributeDef::new(0x0000, DataType::Uint(2), Access::RO);
/// `MaximumOutgoingTransferSize` (uint16).
pub const MAXIMUM_OUTGOING_TRANSFER_SIZE: AttributeDef =
    AttributeDef::new(0x0001, DataType::Uint(2), Access::RO);
/// `PartitionedFrameSize` (uint8 octets, default 80).
pub const PARTITIONED_FRAME_SIZE: AttributeDef =
    AttributeDef::new(0x0002, DataType::Uint(1), Access::RW);
/// `LargeFrameSize` (uint16, multiples of `PartitionedFrameSize`).
pub const LARGE_FRAME_SIZE: AttributeDef = AttributeDef::new(0x0003, DataType::Uint(2), Access::RW);
/// `NumberOfACKFrame` (uint8; 0 = no acknowledgements).
pub const NUMBER_OF_ACK_FRAME: AttributeDef =
    AttributeDef::new(0x0004, DataType::Uint(1), Access::RW);
/// `NACKTimeout` (uint16 milliseconds).
pub const NACK_TIMEOUT: AttributeDef = AttributeDef::new(0x0005, DataType::Uint(2), Access::RO);
/// `InterframeDelay` (uint8 milliseconds, never 0).
pub const INTERFRAME_DELAY: AttributeDef = AttributeDef::new(0x0006, DataType::Uint(1), Access::RW);
/// `NumberOfSendRetries` (uint8).
pub const NUMBER_OF_SEND_RETRIES: AttributeDef =
    AttributeDef::new(0x0007, DataType::Uint(1), Access::RO);
/// `SenderTimeout` (uint16 milliseconds).
pub const SENDER_TIMEOUT: AttributeDef = AttributeDef::new(0x0008, DataType::Uint(2), Access::RO);
/// `ReceiverTimeout` (uint16 milliseconds).
pub const RECEIVER_TIMEOUT: AttributeDef = AttributeDef::new(0x0009, DataType::Uint(2), Access::RO);

/// TransferPartitionedFrame (client → server).
pub const CMD_TRANSFER_PARTITIONED_FRAME: CommandId = CommandId(0x00);
/// ReadHandshakeParam.
pub const CMD_READ_HANDSHAKE_PARAM: CommandId = CommandId(0x01);
/// WriteHandshakeParam.
pub const CMD_WRITE_HANDSHAKE_PARAM: CommandId = CommandId(0x02);
/// MultipleACK (server → client).
pub const CMD_MULTIPLE_ACK: CommandId = CommandId(0x00);
/// ReadHandshakeParamResponse.
pub const CMD_READ_HANDSHAKE_PARAM_RESPONSE: CommandId = CommandId(0x01);

/// Cluster definition.
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[
        CMD_TRANSFER_PARTITIONED_FRAME,
        CMD_READ_HANDSHAKE_PARAM,
        CMD_WRITE_HANDSHAKE_PARAM,
    ],
    generated: &[CMD_MULTIPLE_ACK, CMD_READ_HANDSHAKE_PARAM_RESPONSE],
};

/// Fragmentation Options: first block of an acknowledgement group.
pub const OPTION_FIRST_BLOCK: u8 = 0x01;
/// Fragmentation Options: the PartitionIndicator is two octets.
pub const OPTION_INDICATOR_16: u8 = 0x02;
/// ACK Options: the FirstFrameID and NACKIds are two octets.
pub const ACK_OPTION_ID_16: u8 = 0x01;

/// Largest partitioned block (`PartitionedFrameSize`) this
/// implementation carries (the default is 80).
pub const MAX_BLOCK: usize = 80;
/// Missing blocks one MultipleACK names.
pub const MAX_NACKS: usize = 16;
/// Handshake attribute records in one command.
pub const MAX_HANDSHAKE_ATTRIBUTES: usize = 8;

/// The per-transaction parameters (the cluster attributes that matter
/// to a transfer, exchanged in the handshake).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Params {
    /// `PartitionedFrameSize`.
    pub block_size: u8,
    /// `NumberOfACKFrame` (0: no acknowledgements).
    pub ack_frames: u8,
    /// `NACKTimeout`.
    pub nack_timeout: Duration,
    /// `InterframeDelay`.
    pub interframe_delay: Duration,
    /// `NumberOfSendRetries`.
    pub send_retries: u8,
    /// `SenderTimeout`.
    pub sender_timeout: Duration,
    /// `ReceiverTimeout`.
    pub receiver_timeout: Duration,
}

impl Params {
    /// The Table 9-29 defaults for `aps_ack_wait` (apsAckWaitDuration)
    /// and `interframe_delay` (apsInterframeDelay): 80-octet blocks,
    /// 100 blocks per acknowledgement, 3 retries and the derived
    /// timeouts (§9.6.3.2.1.6, §9.6.3.2.1.9, §9.6.3.2.1.10).
    pub fn defaults(aps_ack_wait: Duration, interframe_delay: Duration) -> Self {
        let ack_frames = 0x64u8;
        let per_group = Duration::from_millis(
            interframe_delay
                .as_millis()
                .saturating_mul(u64::from(ack_frames)),
        );
        let nack_timeout = aps_ack_wait + per_group;
        let sender_timeout = aps_ack_wait + aps_ack_wait + per_group;
        let receiver_timeout = Duration::from_millis(
            aps_ack_wait.as_millis() + interframe_delay.as_millis() + 3 * nack_timeout.as_millis(),
        );
        Params {
            block_size: 0x50,
            ack_frames,
            nack_timeout,
            interframe_delay,
            send_retries: 3,
            sender_timeout,
            receiver_timeout,
        }
    }

    /// Blocks a frame of `len` octets needs (the last one zero-padded).
    pub fn blocks_for(&self, len: usize) -> usize {
        len.div_ceil(usize::from(self.block_size.max(1)))
    }
}

/// TransferPartitionedFrame (§9.6.3.3.1).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TransferPartitionedFrame<'a> {
    /// The first block of an acknowledgement group.
    pub first_block: bool,
    /// The indicator is two octets.
    pub indicator_16: bool,
    /// The overall number of blocks (block 0) or the block index.
    pub indicator: u16,
    /// The block (padded to `PartitionedFrameSize` when last).
    pub frame: &'a [u8],
}

impl<'a> TransferPartitionedFrame<'a> {
    /// Parses the payload.
    pub fn parse(payload: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        let options = r.u8()?;
        let indicator_16 = options & OPTION_INDICATOR_16 != 0;
        let indicator = if indicator_16 {
            r.u16_le()?
        } else {
            u16::from(r.u8()?)
        };
        let n = usize::from(r.u8()?);
        let frame = r.bytes(n)?;
        Ok(TransferPartitionedFrame {
            first_block: options & OPTION_FIRST_BLOCK != 0,
            indicator_16,
            indicator,
            frame,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let mut options = 0;
        if self.first_block {
            options |= OPTION_FIRST_BLOCK;
        }
        if self.indicator_16 {
            options |= OPTION_INDICATOR_16;
        }
        w.u8(options)?;
        if self.indicator_16 {
            w.u16_le(self.indicator)?;
        } else {
            w.u8(
                u8::try_from(self.indicator).map_err(|_| CodecError::Unrepresentable {
                    field: "partition indicator",
                })?,
            )?;
        }
        w.u8(u8::try_from(self.frame.len())
            .map_err(|_| CodecError::Unrepresentable { field: "frame" })?)?;
        w.bytes(self.frame)
    }
}

/// MultipleACK (§9.6.3.4.1).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MultipleAck {
    /// Identifiers are two octets.
    pub id_16: bool,
    /// The first block index of the acknowledged group.
    pub first_frame_id: u16,
    /// Blocks of the group not received (empty: all received).
    pub nack_ids: Vec<u16, MAX_NACKS>,
}

impl MultipleAck {
    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        let options = r.u8()?;
        let id_16 = options & ACK_OPTION_ID_16 != 0;
        let read = |r: &mut Reader<'_>| -> Result<u16, CodecError> {
            if id_16 {
                r.u16_le()
            } else {
                r.u8().map(u16::from)
            }
        };
        let first_frame_id = read(&mut r)?;
        let mut nack_ids = Vec::new();
        while !r.is_empty() {
            nack_ids
                .push(read(&mut r)?)
                .map_err(|_| CodecError::Unrepresentable { field: "nack ids" })?;
        }
        Ok(MultipleAck {
            id_16,
            first_frame_id,
            nack_ids,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(if self.id_16 { ACK_OPTION_ID_16 } else { 0 })?;
        let write = |w: &mut Writer<'_>, v: u16| -> Result<(), CodecError> {
            if self.id_16 {
                w.u16_le(v)
            } else {
                w.u8(u8::try_from(v).map_err(|_| CodecError::Unrepresentable { field: "id" })?)
            }
        };
        write(w, self.first_frame_id)?;
        for id in &self.nack_ids {
            write(w, *id)?;
        }
        Ok(())
    }
}

/// ReadHandshakeParam (§9.6.3.3.2): the partitioned cluster and the
/// attributes asked for.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReadHandshakeParam {
    /// The cluster whose frame is partitioned.
    pub cluster: ClusterId,
    /// Attribute identifiers.
    pub attributes: Vec<u16, MAX_HANDSHAKE_ATTRIBUTES>,
}

impl ReadHandshakeParam {
    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        let cluster = ClusterId(r.u16_le()?);
        let mut attributes = Vec::new();
        while !r.is_empty() {
            attributes
                .push(r.u16_le()?)
                .map_err(|_| CodecError::Unrepresentable {
                    field: "attributes",
                })?;
        }
        Ok(ReadHandshakeParam {
            cluster,
            attributes,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.cluster.0)?;
        for a in &self.attributes {
            w.u16_le(*a)?;
        }
        Ok(())
    }
}

/// WriteHandshakeParam (§9.6.3.3.3): the partitioned cluster and the
/// write attribute records (identifier, type, value) that follow, kept
/// raw for the ZCL attribute codecs to apply.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct WriteHandshakeParam<'a> {
    /// The cluster whose frame is partitioned.
    pub cluster: ClusterId,
    /// The write attribute records.
    pub records: &'a [u8],
}

impl<'a> WriteHandshakeParam<'a> {
    /// Parses the payload.
    pub fn parse(payload: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        let cluster = ClusterId(r.u16_le()?);
        Ok(WriteHandshakeParam {
            cluster,
            records: r.take_rest(),
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.cluster.0)?;
        w.bytes(self.records)
    }
}

/// ReadHandshakeParamResponse (§9.6.3.4.2): the partitioned cluster and
/// the read attribute status records that follow, raw.
pub type ReadHandshakeParamResponse<'a> = WriteHandshakeParam<'a>;

/// Builds a server with the Table 9-29 attributes at `params` and the
/// transfer sizes `incoming` / `outgoing` (multiples of the block size).
pub fn server<const A: usize>(
    params: &Params,
    incoming: u16,
    outgoing: u16,
) -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    let u = |width: u8, value: u64| Value::Uint { width, value };
    c.add_attribute(MAXIMUM_INCOMING_TRANSFER_SIZE, &u(2, u64::from(incoming)))?;
    c.add_attribute(MAXIMUM_OUTGOING_TRANSFER_SIZE, &u(2, u64::from(outgoing)))?;
    c.add_attribute(PARTITIONED_FRAME_SIZE, &u(1, u64::from(params.block_size)))?;
    c.add_attribute(LARGE_FRAME_SIZE, &u(2, 0x0500))?;
    c.add_attribute(NUMBER_OF_ACK_FRAME, &u(1, u64::from(params.ack_frames)))?;
    c.add_attribute(
        NACK_TIMEOUT,
        &u(2, params.nack_timeout.as_millis().min(0xFFFF)),
    )?;
    c.add_attribute(
        INTERFRAME_DELAY,
        &u(1, params.interframe_delay.as_millis().clamp(1, 0xFF)),
    )?;
    c.add_attribute(
        NUMBER_OF_SEND_RETRIES,
        &u(1, u64::from(params.send_retries)),
    )?;
    c.add_attribute(
        SENDER_TIMEOUT,
        &u(2, params.sender_timeout.as_millis().min(0xFFFF)),
    )?;
    c.add_attribute(
        RECEIVER_TIMEOUT,
        &u(2, params.receiver_timeout.as_millis().min(0xFFFF)),
    )?;
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF.mirrored(), Role::Client)
}

/// The parameters a server instance holds.
pub fn params_of<const A: usize>(c: &ClusterInstance<A>) -> Params {
    let ms = |id, default: u64| Duration::from_millis(c.u64(id).unwrap_or(default));
    Params {
        block_size: c.u8(PARTITIONED_FRAME_SIZE.id).unwrap_or(0x50),
        ack_frames: c.u8(NUMBER_OF_ACK_FRAME.id).unwrap_or(0x64),
        nack_timeout: ms(NACK_TIMEOUT.id, 0),
        interframe_delay: ms(INTERFRAME_DELAY.id, 10),
        send_retries: c.u8(NUMBER_OF_SEND_RETRIES.id).unwrap_or(3),
        sender_timeout: ms(SENDER_TIMEOUT.id, 0),
        receiver_timeout: ms(RECEIVER_TIMEOUT.id, 0),
    }
}

// ----- Sender -----

/// What the sender wants next.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SendStep {
    /// Send this block at `at` (the interframe delay from the previous).
    Block {
        /// When.
        at: Instant,
        /// Index of the block.
        index: u16,
        /// The command.
        first_block: bool,
    },
    /// Every block of the group is out: wait for the MultipleACK until
    /// `until`.
    AwaitAck {
        /// The sender timeout.
        until: Instant,
    },
    /// The large frame is delivered.
    Done,
    /// No MultipleACK within the retries: the transfer failed.
    Failed,
}

/// The sending side of one transaction over `frame` (§9.6.3.3.1,
/// §9.6.3.4.1.1): blocks go out in groups of `NumberOfACKFrame`, each
/// group is acknowledged (or its missing blocks resent) before the next.
#[derive(Clone, Debug)]
pub struct Sender {
    params: Params,
    len: usize,
    total: u16,
    /// First index of the current group.
    group_start: u16,
    /// Indices still to send in this round (the group, or the NACKs).
    pending: Vec<u16, MAX_NACKS>,
    /// Blocks sent in the current group that await acknowledgement.
    awaiting: bool,
    retries_left: u8,
    next_at: Instant,
    ack_until: Option<Instant>,
    done: bool,
    failed: bool,
    /// Blocks a full group is queued from (`pending` holds at most
    /// `MAX_NACKS` explicit indices; a group is enumerated instead).
    cursor: u16,
    group_end: u16,
}

impl Sender {
    /// A transaction for a frame of `len` octets starting at `now`
    /// (`None` when the frame needs more blocks than a 16-bit indicator
    /// holds, or is empty).
    pub fn new(params: Params, len: usize, now: Instant) -> Option<Self> {
        if len == 0 {
            return None;
        }
        let total = u16::try_from(params.blocks_for(len)).ok()?;
        let mut s = Sender {
            params,
            len,
            total,
            group_start: 0,
            pending: Vec::new(),
            awaiting: false,
            retries_left: params.send_retries,
            next_at: now,
            ack_until: None,
            done: false,
            failed: false,
            cursor: 0,
            group_end: 0,
        };
        s.start_group(0, now);
        Some(s)
    }

    /// Blocks in total.
    pub const fn total_blocks(&self) -> u16 {
        self.total
    }

    fn group_size(&self) -> u16 {
        if self.params.ack_frames == 0 {
            self.total
        } else {
            u16::from(self.params.ack_frames)
        }
    }

    fn start_group(&mut self, start: u16, now: Instant) {
        self.group_start = start;
        self.cursor = start;
        self.group_end = start.saturating_add(self.group_size()).min(self.total);
        self.pending.clear();
        self.awaiting = false;
        self.ack_until = None;
        self.retries_left = self.params.send_retries;
        self.next_at = now;
    }

    /// The next block index to send, if any is due in this round.
    fn next_index(&mut self) -> Option<u16> {
        if !self.pending.is_empty() {
            return Some(self.pending.remove(0));
        }
        if self.cursor < self.group_end {
            let i = self.cursor;
            self.cursor += 1;
            return Some(i);
        }
        None
    }

    /// What to do at `now`. A `Block` step is answered by
    /// [`Sender::block`] (which builds the command) once sent.
    pub fn step(&mut self, now: Instant) -> SendStep {
        if self.done {
            return SendStep::Done;
        }
        if self.failed {
            return SendStep::Failed;
        }
        if self.awaiting {
            let until = self.ack_until.unwrap_or(now);
            if now.has_reached(until) {
                // §9.6.3.4.1.1: no MultipleACK in time: resend the group
                // up to NumberOfSendRetries.
                if self.retries_left == 0 {
                    self.failed = true;
                    return SendStep::Failed;
                }
                self.retries_left -= 1;
                self.cursor = self.group_start;
                self.pending.clear();
                self.awaiting = false;
                self.next_at = now;
            } else {
                return SendStep::AwaitAck { until };
            }
        }
        match self.peek_index() {
            Some(index) => SendStep::Block {
                at: self.next_at,
                index,
                first_block: index == self.group_start,
            },
            None => {
                if self.params.ack_frames == 0 {
                    // Unacknowledged transfer: done once everything went.
                    self.done = true;
                    SendStep::Done
                } else {
                    self.awaiting = true;
                    let until = self.next_at + self.params.sender_timeout;
                    self.ack_until = Some(until);
                    SendStep::AwaitAck { until }
                }
            }
        }
    }

    fn peek_index(&self) -> Option<u16> {
        self.pending
            .first()
            .copied()
            .or((self.cursor < self.group_end).then_some(self.cursor))
    }

    /// Builds the TransferPartitionedFrame of the block the last
    /// [`Sender::step`] asked for, from `frame`, into `out`, and marks
    /// it sent at `now`. Returns the encoded length.
    pub fn block(
        &mut self,
        frame: &[u8],
        now: Instant,
        out: &mut [u8],
    ) -> Result<usize, CodecError> {
        let index = self.next_index().ok_or(CodecError::InvalidField {
            field: "block",
            value: 0,
        })?;
        let size = usize::from(self.params.block_size.max(1));
        let start = usize::from(index) * size;
        let mut padded = [0u8; MAX_BLOCK];
        let n = size.min(MAX_BLOCK);
        let src = frame.get(start..(start + n).min(self.len)).unwrap_or(&[]);
        padded[..src.len()].copy_from_slice(src);
        let indicator = if index == 0 { self.total } else { index };
        let cmd = TransferPartitionedFrame {
            first_block: index == self.group_start,
            indicator_16: self.total > 0xFF,
            indicator,
            frame: &padded[..n],
        };
        let mut w = Writer::new(out);
        cmd.encode(&mut w)?;
        self.next_at = now + self.params.interframe_delay;
        Ok(w.position())
    }

    /// A MultipleACK arrived at `now`: with no NACKIds the next group
    /// starts (or the transfer is done), otherwise the named blocks are
    /// resent; the retries and the sender timeout restart either way.
    pub fn on_multiple_ack(&mut self, ack: &MultipleAck, now: Instant) {
        if self.done || self.failed || ack.first_frame_id != self.group_start {
            return;
        }
        if ack.nack_ids.is_empty() {
            if self.group_end >= self.total {
                self.done = true;
            } else {
                let next = self.group_end;
                self.start_group(next, now);
            }
            return;
        }
        if self.retries_left == 0 {
            self.failed = true;
            return;
        }
        self.retries_left -= 1;
        self.pending.clear();
        for id in &ack.nack_ids {
            if *id >= self.group_start && *id < self.group_end {
                let _ = self.pending.push(*id);
            }
        }
        self.cursor = self.group_end;
        self.awaiting = false;
        self.next_at = now;
    }

    /// When the sender next needs a [`Sender::step`].
    pub fn next_deadline(&self) -> Option<Instant> {
        if self.done || self.failed {
            return None;
        }
        if self.awaiting {
            self.ack_until
        } else {
            Some(self.next_at)
        }
    }
}

// ----- Receiver -----

/// What the receiver wants after a block or a poll.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ReceiveStep {
    /// Nothing to send.
    Wait,
    /// Send this MultipleACK.
    Ack(MultipleAck),
    /// The large frame is complete (`len` octets in the buffer).
    Complete {
        /// Length of the reassembled frame (the padded last block
        /// included: the partitioned cluster knows its own length).
        len: usize,
    },
    /// The transfer timed out (`ReceiverTimeout`) and was abandoned.
    Abandoned,
}

/// The receiving side of one transaction into a buffer of `N` octets
/// (§9.6.3.3.1.1): every `NumberOfACKFrame` blocks, or after
/// `NACKTimeout`, a MultipleACK names what is missing; silence for
/// `ReceiverTimeout` abandons the transfer.
#[derive(Clone, Debug)]
pub struct Receiver<const N: usize> {
    params: Params,
    buffer: Vec<u8, N>,
    received: Vec<bool, 256>,
    total: Option<u16>,
    group_start: u16,
    nack_at: Option<Instant>,
    abandon_at: Option<Instant>,
    complete: bool,
}

impl<const N: usize> Receiver<N> {
    /// A receiver with `params` (the handshake's, or the server's).
    pub fn new(params: Params) -> Self {
        Receiver {
            params,
            buffer: Vec::new(),
            received: Vec::new(),
            total: None,
            group_start: 0,
            nack_at: None,
            abandon_at: None,
            complete: false,
        }
    }

    /// The reassembled frame so far (complete once
    /// [`ReceiveStep::Complete`] was returned).
    pub fn frame(&self) -> &[u8] {
        &self.buffer
    }

    fn group_end(&self) -> u16 {
        let total = self.total.unwrap_or(0);
        if self.params.ack_frames == 0 {
            total
        } else {
            self.group_start
                .saturating_add(u16::from(self.params.ack_frames))
                .min(total)
        }
    }

    fn group_complete(&self) -> bool {
        (self.group_start..self.group_end())
            .all(|i| self.received.get(usize::from(i)) == Some(&true))
    }

    fn missing(&self) -> Vec<u16, MAX_NACKS> {
        let mut v = Vec::new();
        for i in self.group_start..self.group_end() {
            if self.received.get(usize::from(i)) != Some(&true) && v.push(i).is_err() {
                break;
            }
        }
        v
    }

    fn ack(&self) -> MultipleAck {
        MultipleAck {
            id_16: self.total.unwrap_or(0) > 0xFF,
            first_frame_id: self.group_start,
            nack_ids: self.missing(),
        }
    }

    /// A TransferPartitionedFrame at `now`.
    pub fn on_block(&mut self, cmd: &TransferPartitionedFrame<'_>, now: Instant) -> ReceiveStep {
        if self.complete {
            return ReceiveStep::Complete {
                len: self.buffer.len(),
            };
        }
        let size = usize::from(self.params.block_size.max(1));
        // The first block announces the total and sizes the buffers.
        let index = if self.total.is_none() {
            if cmd.indicator == 0 || usize::from(cmd.indicator) * size > N {
                return ReceiveStep::Wait;
            }
            self.total = Some(cmd.indicator);
            self.received.clear();
            for _ in 0..cmd.indicator {
                let _ = self.received.push(false);
            }
            self.buffer.clear();
            let _ = self
                .buffer
                .resize_default(usize::from(cmd.indicator) * size);
            self.abandon_at = Some(now + self.params.receiver_timeout);
            0
        } else if cmd.indicator == 0 || cmd.indicator == self.total.unwrap_or(0) && !cmd.first_block
        {
            // Block 0 again (its indicator is the total).
            0
        } else {
            cmd.indicator
        };
        let Some(total) = self.total else {
            return ReceiveStep::Wait;
        };
        if index >= total {
            return ReceiveStep::Wait;
        }
        let start = usize::from(index) * size;
        if let Some(slot) = self.buffer.get_mut(start..start + size) {
            let n = cmd.frame.len().min(size);
            slot[..n].copy_from_slice(&cmd.frame[..n]);
        }
        if let Some(r) = self.received.get_mut(usize::from(index)) {
            *r = true;
        }
        self.abandon_at = Some(now + self.params.receiver_timeout);
        if self.nack_at.is_none() && self.params.ack_frames != 0 {
            self.nack_at = Some(now + self.params.nack_timeout);
        }
        // A block outside the current group: the sender moved on
        // (its ACK was lost); the group follows the block.
        if index >= self.group_end() {
            let n = u16::from(self.params.ack_frames.max(1));
            self.group_start = index - index % n;
        }
        if self.received.iter().all(|r| *r) {
            self.complete = true;
            return ReceiveStep::Complete {
                len: self.buffer.len(),
            };
        }
        if self.params.ack_frames != 0 && self.group_complete() {
            let ack = self.ack();
            self.group_start = self.group_end();
            self.nack_at = None;
            return ReceiveStep::Ack(ack);
        }
        ReceiveStep::Wait
    }

    /// Time passes: the NACKTimeout names the blocks still missing, the
    /// ReceiverTimeout abandons the transfer.
    pub fn poll(&mut self, now: Instant) -> ReceiveStep {
        if self.complete {
            return ReceiveStep::Wait;
        }
        if let Some(at) = self.abandon_at
            && now.has_reached(at)
        {
            self.abandon_at = None;
            self.nack_at = None;
            self.total = None;
            return ReceiveStep::Abandoned;
        }
        if let Some(at) = self.nack_at
            && now.has_reached(at)
        {
            self.nack_at = Some(now + self.params.nack_timeout);
            return ReceiveStep::Ack(self.ack());
        }
        ReceiveStep::Wait
    }

    /// When the receiver next needs a poll.
    pub fn next_deadline(&self) -> Option<Instant> {
        if self.complete {
            return None;
        }
        match (self.nack_at, self.abandon_at) {
            (Some(a), Some(b)) => Some(if a.as_millis() <= b.as_millis() { a } else { b }),
            (a, b) => a.or(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> Params {
        Params {
            block_size: 4,
            ack_frames: 3,
            nack_timeout: Duration::from_millis(100),
            interframe_delay: Duration::from_millis(10),
            send_retries: 2,
            sender_timeout: Duration::from_millis(500),
            receiver_timeout: Duration::from_millis(2000),
        }
    }

    #[test]
    fn codecs_round_trip() {
        let t = TransferPartitionedFrame {
            first_block: true,
            indicator_16: true,
            indicator: 300,
            frame: &[1, 2, 3, 4],
        };
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        t.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(&buf[..n], &[0x03, 0x2C, 0x01, 4, 1, 2, 3, 4]);
        assert_eq!(TransferPartitionedFrame::parse(&buf[..n]).unwrap(), t);
        let a = MultipleAck {
            id_16: false,
            first_frame_id: 3,
            nack_ids: Vec::from_slice(&[4, 5]).unwrap(),
        };
        let mut w = Writer::new(&mut buf);
        a.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(&buf[..n], &[0x00, 3, 4, 5]);
        assert_eq!(MultipleAck::parse(&buf[..n]).unwrap(), a);
        let r = ReadHandshakeParam {
            cluster: ClusterId(0x0b03),
            attributes: Vec::from_slice(&[0x0002, 0x0004]).unwrap(),
        };
        let mut w = Writer::new(&mut buf);
        r.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(ReadHandshakeParam::parse(&buf[..n]).unwrap(), r);
        let wr = WriteHandshakeParam {
            cluster: ClusterId(0x0b03),
            records: &[0x02, 0x00, 0x20, 0x08],
        };
        let mut w = Writer::new(&mut buf);
        wr.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(WriteHandshakeParam::parse(&buf[..n]).unwrap(), wr);
        let d = Params::defaults(Duration::from_millis(1600), Duration::from_millis(10));
        assert_eq!(d.nack_timeout, Duration::from_millis(1600 + 1000));
        assert_eq!(d.sender_timeout, Duration::from_millis(3200 + 1000));
        assert_eq!(d.blocks_for(100), 2);
        let c: ClusterInstance<12> = server(&d, 0x0500, 0x0500).unwrap();
        assert_eq!(params_of(&c), d);
    }

    /// Runs a transfer between a sender and a receiver over a lossy
    /// link: `drop` says which (index, attempt) transmissions vanish.
    fn transfer(frame: &[u8], mut drop: impl FnMut(u16, u32) -> bool) -> Option<usize> {
        let p = params();
        let mut now = Instant::from_millis(0);
        let mut s = Sender::new(p, frame.len(), now).unwrap();
        let mut r: Receiver<64> = Receiver::new(p);
        let mut attempts = [0u32; 32];
        let mut buf = [0u8; 64];
        for _ in 0..200 {
            match s.step(now) {
                SendStep::Block { at, index, .. } => {
                    now = at;
                    let n = s.block(frame, now, &mut buf).unwrap();
                    let attempt = attempts[usize::from(index)];
                    attempts[usize::from(index)] += 1;
                    if drop(index, attempt) {
                        continue;
                    }
                    let cmd = TransferPartitionedFrame::parse(&buf[..n]).unwrap();
                    match r.on_block(&cmd, now) {
                        ReceiveStep::Ack(a) => s.on_multiple_ack(&a, now),
                        ReceiveStep::Complete { len } => return Some(len),
                        ReceiveStep::Wait => {}
                        ReceiveStep::Abandoned => return None,
                    }
                }
                SendStep::AwaitAck { until } => {
                    // The receiver's NACK timer runs meanwhile.
                    let next = r.next_deadline().unwrap_or(until);
                    now = if next.as_millis() < until.as_millis() {
                        next
                    } else {
                        until
                    };
                    match r.poll(now) {
                        ReceiveStep::Ack(a) => s.on_multiple_ack(&a, now),
                        ReceiveStep::Abandoned => return None,
                        _ => {}
                    }
                }
                SendStep::Done => return Some(r.frame().len()),
                SendStep::Failed => return None,
            }
        }
        None
    }

    #[test]
    fn a_large_frame_crosses_a_lossless_link_in_acknowledged_groups() {
        let frame: [u8; 30] = core::array::from_fn(|i| i as u8);
        assert_eq!(transfer(&frame, |_, _| false), Some(32));
        let p = params();
        let mut s = Sender::new(p, 30, Instant::from_millis(0)).unwrap();
        assert_eq!(s.total_blocks(), 8);
        // Block 0 carries the total, block 3 opens the second group.
        let mut buf = [0u8; 16];
        let _ = s.step(Instant::from_millis(0));
        let n = s.block(&frame, Instant::from_millis(0), &mut buf).unwrap();
        let b0 = TransferPartitionedFrame::parse(&buf[..n]).unwrap();
        assert_eq!(
            (b0.first_block, b0.indicator, b0.frame),
            (true, 8, &[0, 1, 2, 3][..])
        );
    }

    #[test]
    fn lost_blocks_are_named_by_the_multiple_ack_and_resent() {
        let frame: [u8; 30] = core::array::from_fn(|i| (i * 3) as u8);
        // Block 4 lost on its first attempt, block 1 twice.
        let mut r: Receiver<64> = Receiver::new(params());
        let len = transfer(&frame, |i, a| (i == 4 && a == 0) || (i == 1 && a < 2)).unwrap();
        assert_eq!(len, 32);
        // The receiver's view of a lost block: the NACK timer names it.
        let now = Instant::from_millis(0);
        let cmd = TransferPartitionedFrame {
            first_block: true,
            indicator_16: false,
            indicator: 8,
            frame: &[9, 9, 9, 9],
        };
        assert_eq!(r.on_block(&cmd, now), ReceiveStep::Wait);
        let cmd = TransferPartitionedFrame {
            first_block: false,
            indicator_16: false,
            indicator: 2,
            frame: &[8, 8, 8, 8],
        };
        assert_eq!(r.on_block(&cmd, now), ReceiveStep::Wait);
        assert_eq!(r.poll(now + Duration::from_millis(99)), ReceiveStep::Wait);
        assert_eq!(
            r.poll(now + Duration::from_millis(100)),
            ReceiveStep::Ack(MultipleAck {
                id_16: false,
                first_frame_id: 0,
                nack_ids: Vec::from_slice(&[1]).unwrap(),
            })
        );
        // Silence abandons it.
        assert_eq!(
            r.poll(now + Duration::from_millis(2100)),
            ReceiveStep::Abandoned
        );
    }

    #[test]
    fn a_sender_without_acknowledgements_gives_up() {
        let frame = [1u8; 8];
        let p = params();
        let mut s = Sender::new(p, 8, Instant::from_millis(0)).unwrap();
        let mut buf = [0u8; 16];
        let mut now = Instant::from_millis(0);
        let mut sent = 0;
        loop {
            match s.step(now) {
                SendStep::Block { at, .. } => {
                    now = at;
                    s.block(&frame, now, &mut buf).unwrap();
                    sent += 1;
                }
                SendStep::AwaitAck { until } => now = until,
                SendStep::Failed => break,
                SendStep::Done => panic!("never acknowledged"),
            }
        }
        // Two blocks, sent once and retried twice.
        assert_eq!(sent, 2 * 3);
        // Unacknowledged mode: done after one pass.
        let mut s = Sender::new(Params { ack_frames: 0, ..p }, 8, Instant::from_millis(0)).unwrap();
        let mut n = 0;
        loop {
            match s.step(now) {
                SendStep::Block { at, .. } => {
                    now = at;
                    s.block(&frame, now, &mut buf).unwrap();
                    n += 1;
                }
                SendStep::Done => break,
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(n, 2);
    }
}
