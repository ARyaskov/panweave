//! The inter-PAN data service for applications (R23.2 Annex G,
//! INTRP-DATA.request / .indication): application frames exchanged
//! between devices that need not share a network, carried in a MAC
//! data frame with the stub NWK header and the inter-PAN APS header.
//! Frames of the Touchlink Commissioning cluster keep going to the
//! touchlink machines; every other inter-PAN frame reaches the
//! application as [`StackEvent::InterPanData`], unprotected with the
//! sender's link key when it was secured.

use heapless::Vec;
use panweave_aps::interpan::{self, InterPanDelivery, InterPanHeader};
use panweave_mac::frame::{Frame as MacFrame, MacAddress};
use panweave_security::cipher::BlockCipher;
use panweave_storage::Storage;
use panweave_types::{
    Channel, ClusterId, CryptoRng, ExtendedAddress, GroupAddress, NwkStatus, PanId, ProfileId,
    ShortAddress,
};

use crate::stack::{Stack, StackEvent};

/// Largest inter-PAN application frame (the MAC payload less the stub
/// headers and security overhead).
pub const MAX_INTER_PAN_ASDU: usize = 80;

/// Where an inter-PAN frame goes (INTRP-DATA.request DstAddrMode).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum InterPanTarget {
    /// Every device on the channel (broadcast PAN, broadcast address).
    Broadcast,
    /// One device by IEEE address.
    Device(ExtendedAddress),
    /// A device of another network by its network address.
    Short(ShortAddress),
    /// A group of another network.
    Group(GroupAddress),
}

/// A received inter-PAN application frame.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InterPanIndication {
    /// Sender (the MAC extended source address).
    pub src: ExtendedAddress,
    /// Sender's PAN.
    pub src_pan: PanId,
    /// Destination PAN of the frame.
    pub dst_pan: PanId,
    /// Delivery mode.
    pub delivery: InterPanDelivery,
    /// Profile.
    pub profile: ProfileId,
    /// Cluster.
    pub cluster: ClusterId,
    /// The application frame.
    pub asdu: Vec<u8, MAX_INTER_PAN_ASDU>,
    /// Protected with the link key shared with `src`.
    pub secured: bool,
    /// Received signal strength.
    pub rssi: i8,
    /// Channel the frame arrived on.
    pub channel: Channel,
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Stack<C, R, S> {
    /// INTRP-DATA.request: sends `asdu` of `profile` / `cluster` to
    /// `target` on `dst_pan` (the broadcast PAN reaches everyone on the
    /// channel), from this device's PAN and IEEE address. With
    /// `secured`, the frame is protected with the link key shared with
    /// the target device (`Device` targets only; `NoKey` otherwise).
    pub fn inter_pan_request(
        &mut self,
        target: InterPanTarget,
        dst_pan: PanId,
        profile: ProfileId,
        cluster: ClusterId,
        asdu: &[u8],
        secured: bool,
    ) -> Result<(), NwkStatus> {
        if asdu.len() > MAX_INTER_PAN_ASDU {
            return Err(NwkStatus::InvalidParameter);
        }
        let (mac_dst, delivery, ack) = match target {
            InterPanTarget::Broadcast => (
                MacAddress::Short(ShortAddress::BROADCAST_ALL),
                InterPanDelivery::Broadcast,
                false,
            ),
            InterPanTarget::Device(e) => (MacAddress::Extended(e), InterPanDelivery::Unicast, true),
            InterPanTarget::Short(s) => (MacAddress::Short(s), InterPanDelivery::Unicast, true),
            InterPanTarget::Group(g) => (
                MacAddress::Short(ShortAddress::BROADCAST_ALL),
                InterPanDelivery::Group(g),
                false,
            ),
        };
        let header = InterPanHeader::new(delivery, cluster, profile);
        let mut buf = [0u8; 127];
        let n = if secured {
            let InterPanTarget::Device(partner) = target else {
                return Err(NwkStatus::NoKey);
            };
            let level = self.aps.config.security_level;
            let local = self.config.ieee;
            interpan::secure(
                &mut self.aps.security,
                &mut buf,
                &header,
                asdu,
                level,
                partner,
                local,
            )
            .map_err(|_| NwkStatus::NoKey)?
        } else {
            let mut w = panweave_codec::Writer::new(&mut buf);
            header
                .encode(&mut w)
                .and_then(|()| w.bytes(asdu))
                .map_err(|_| NwkStatus::InvalidParameter)?;
            w.position()
        };
        let src_pan = self.nwk.nib.pan_id;
        self.mac
            .data_request_inter_pan(dst_pan, mac_dst, src_pan, buf.get(..n).unwrap_or(&[]), ack)
            .map_err(|_| NwkStatus::InvalidRequest)?;
        self.pump();
        Ok(())
    }

    /// An inter-PAN frame of a cluster other than Touchlink
    /// Commissioning: unprotect it when secured and hand it to the
    /// application (INTRP-DATA.indication).
    pub(crate) fn on_inter_pan_data(&mut self, frame: &MacFrame<'_>, rssi: i8, channel: Channel) {
        let Some(src) = frame.header.src.extended() else {
            return;
        };
        let Some(src_pan) = frame.header.effective_src_pan() else {
            return;
        };
        let dst_pan = frame.header.dst_pan.unwrap_or(PanId::BROADCAST);
        let Ok((header, plain)) = InterPanHeader::decode(frame.payload) else {
            return;
        };
        let (asdu, secured) = if header.secured {
            let mut buf = [0u8; 127];
            let Some(dst) = buf.get_mut(..frame.payload.len()) else {
                return;
            };
            dst.copy_from_slice(frame.payload);
            let level = self.aps.config.security_level;
            let Ok((_, _, range)) = interpan::unsecure(
                &mut self.aps.security,
                &mut buf[..frame.payload.len()],
                level,
                Some(src),
            ) else {
                self.aps.stats.security_dropped = self.aps.stats.security_dropped.saturating_add(1);
                return;
            };
            let Some(bytes) = buf.get(range) else {
                return;
            };
            (Vec::from_slice(bytes), true)
        } else {
            (Vec::from_slice(plain), false)
        };
        let Ok(asdu) = asdu else {
            return;
        };
        self.push_event(StackEvent::InterPanData(InterPanIndication {
            src,
            src_pan,
            dst_pan,
            delivery: header.delivery,
            profile: header.profile,
            cluster: header.cluster,
            asdu,
            secured,
            rssi,
            channel,
        }));
    }
}
