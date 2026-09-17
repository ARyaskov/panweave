//! Price cluster (SE 1.4a Annex D.4): the Publish Price command with its
//! optional fields, the client commands Get Current Price / Get
//! Scheduled Prices / Price Acknowledgement, and a client-side price
//! table applying the overlap rules of D.4.2.4.1. The block, tariff,
//! CO2, billing and credit commands are not implemented.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{ClusterId, CommandId};
use panweave_zcl::cluster::ClusterDef;

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0700);

/// Client → server: Get Current Price.
pub const CMD_GET_CURRENT_PRICE: CommandId = CommandId(0x00);
/// Client → server: Get Scheduled Prices.
pub const CMD_GET_SCHEDULED_PRICES: CommandId = CommandId(0x01);
/// Client → server: Price Acknowledgement.
pub const CMD_PRICE_ACKNOWLEDGEMENT: CommandId = CommandId(0x02);
/// Server → client: Publish Price.
pub const CMD_PUBLISH_PRICE: CommandId = CommandId(0x00);

/// Client cluster definition (the mandatory commands).
pub const CLIENT_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[CMD_PUBLISH_PRICE],
    generated: &[
        CMD_GET_CURRENT_PRICE,
        CMD_GET_SCHEDULED_PRICES,
        CMD_PRICE_ACKNOWLEDGEMENT,
    ],
};

/// Server cluster definition (the mandatory commands).
pub const SERVER_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[
        CMD_GET_CURRENT_PRICE,
        CMD_GET_SCHEDULED_PRICES,
        CMD_PRICE_ACKNOWLEDGEMENT,
    ],
    generated: &[CMD_PUBLISH_PRICE],
};

/// Longest Rate Label (12 characters).
pub const MAX_RATE_LABEL_LEN: usize = 12;
/// Duration "until changed".
pub const DURATION_UNTIL_CHANGED: u16 = 0xFFFF;
/// Price Ratio / Generation Price Ratio "not used".
pub const RATIO_UNUSED: u8 = 0xFF;
/// Generation Price / Alternate Cost "not used".
pub const PRICE_UNUSED: u32 = 0xFFFF_FFFF;
/// Alternate Cost Unit / Trailing Digit / Number of Block Thresholds
/// "not used".
pub const OCTET_UNUSED: u8 = 0xFF;

/// Price Control bits (Table D-100).
pub mod price_control {
    /// Price Acknowledgement required.
    pub const ACKNOWLEDGEMENT_REQUIRED: u8 = 0x01;
    /// The total number of tiers exceeds 15.
    pub const TOTAL_TIERS_EXCEED_15: u8 = 0x02;
}

/// Publish Price payload (Figure D-74). Trailing optional fields are
/// absent (`None`) when a shorter frame is received and omitted from the
/// encoding when `None`; the earlier optional fields carry their "not
/// used" values instead.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublishPrice<'a> {
    /// Provider ID.
    pub provider_id: u32,
    /// Rate Label (UTF-8, up to 12 characters).
    pub rate_label: &'a [u8],
    /// Issuer Event ID.
    pub issuer_event_id: u32,
    /// The sender's current time (UTC seconds).
    pub current_time: u32,
    /// Unit of Measure (Metering enumeration).
    pub unit_of_measure: u8,
    /// Currency (ISO 4217).
    pub currency: u16,
    /// Price Trailing Digit (high nibble) and Price Tier (low nibble).
    pub trailing_digit_and_tier: u8,
    /// Number of Price Tiers (high nibble) and Register Tier (low nibble).
    pub tiers_and_register: u8,
    /// Start time (UTC seconds; 0 = now).
    pub start_time: u32,
    /// Duration in minutes (0xFFFF = until changed).
    pub duration_minutes: u16,
    /// Price.
    pub price: u32,
    /// Price Ratio in tenths (0xFF unused).
    pub price_ratio: u8,
    /// Generation Price (0xFFFFFFFF unused).
    pub generation_price: u32,
    /// Generation Price Ratio (0xFF unused).
    pub generation_price_ratio: u8,
    /// Alternate Cost Delivered (0xFFFFFFFF unused).
    pub alternate_cost_delivered: u32,
    /// Alternate Cost Unit (0xFF unused).
    pub alternate_cost_unit: u8,
    /// Alternate Cost Trailing Digit (0xFF unused).
    pub alternate_cost_trailing_digit: u8,
    /// Number of Block Thresholds (0xFF unused).
    pub number_of_block_thresholds: u8,
    /// Price Control (0 = not used).
    pub price_control: u8,
    /// Number of Generation Tiers.
    pub number_of_generation_tiers: Option<u8>,
    /// Generation Tier.
    pub generation_tier: Option<u8>,
    /// Extended Number of Price Tiers.
    pub extended_number_of_price_tiers: Option<u8>,
    /// Extended Price Tier.
    pub extended_price_tier: Option<u8>,
    /// Extended Register Tier.
    pub extended_register_tier: Option<u8>,
}

fn opt_u8(r: &mut Reader<'_>) -> Result<Option<u8>, CodecError> {
    if r.remaining() >= 1 {
        r.u8().map(Some)
    } else {
        Ok(None)
    }
}

impl<'a> PublishPrice<'a> {
    /// A price with every optional field "not used".
    pub const fn new(
        provider_id: u32,
        rate_label: &'a [u8],
        issuer_event_id: u32,
        current_time: u32,
        start_time: u32,
        duration_minutes: u16,
        price: u32,
    ) -> Self {
        PublishPrice {
            provider_id,
            rate_label,
            issuer_event_id,
            current_time,
            unit_of_measure: 0,
            currency: 0,
            trailing_digit_and_tier: 0,
            tiers_and_register: 0,
            start_time,
            duration_minutes,
            price,
            price_ratio: RATIO_UNUSED,
            generation_price: PRICE_UNUSED,
            generation_price_ratio: RATIO_UNUSED,
            alternate_cost_delivered: PRICE_UNUSED,
            alternate_cost_unit: OCTET_UNUSED,
            alternate_cost_trailing_digit: OCTET_UNUSED,
            number_of_block_thresholds: OCTET_UNUSED,
            price_control: 0,
            number_of_generation_tiers: None,
            generation_tier: None,
            extended_number_of_price_tiers: None,
            extended_price_tier: None,
            extended_register_tier: None,
        }
    }

    /// Parses the payload; SE 1.0 frames ending after the Price field
    /// are accepted with the later fields "not used".
    pub fn parse(bytes: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let provider_id = r.u32_le()?;
        let len = r.u8()?;
        if usize::from(len) > MAX_RATE_LABEL_LEN {
            return Err(CodecError::InvalidField {
                field: "Rate Label",
                value: u32::from(len),
            });
        }
        let rate_label = r.bytes(usize::from(len))?;
        let mut p = PublishPrice::new(provider_id, rate_label, r.u32_le()?, r.u32_le()?, 0, 0, 0);
        p.unit_of_measure = r.u8()?;
        p.currency = r.u16_le()?;
        p.trailing_digit_and_tier = r.u8()?;
        p.tiers_and_register = r.u8()?;
        p.start_time = r.u32_le()?;
        p.duration_minutes = r.u16_le()?;
        p.price = r.u32_le()?;
        if r.remaining() == 0 {
            return Ok(p);
        }
        p.price_ratio = r.u8()?;
        p.generation_price = r.u32_le()?;
        p.generation_price_ratio = r.u8()?;
        p.alternate_cost_delivered = r.u32_le()?;
        p.alternate_cost_unit = r.u8()?;
        p.alternate_cost_trailing_digit = r.u8()?;
        if let Some(v) = opt_u8(&mut r)? {
            p.number_of_block_thresholds = v;
        }
        if let Some(v) = opt_u8(&mut r)? {
            p.price_control = v;
        }
        p.number_of_generation_tiers = opt_u8(&mut r)?;
        p.generation_tier = opt_u8(&mut r)?;
        p.extended_number_of_price_tiers = opt_u8(&mut r)?;
        p.extended_price_tier = opt_u8(&mut r)?;
        p.extended_register_tier = opt_u8(&mut r)?;
        Ok(p)
    }

    /// Encodes the payload up to the last present optional field.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let len = u8::try_from(self.rate_label.len())
            .ok()
            .filter(|l| usize::from(*l) <= MAX_RATE_LABEL_LEN)
            .ok_or(CodecError::InvalidField {
                field: "Rate Label",
                value: 0,
            })?;
        w.u32_le(self.provider_id)?;
        w.u8(len)?;
        w.bytes(self.rate_label)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.current_time)?;
        w.u8(self.unit_of_measure)?;
        w.u16_le(self.currency)?;
        w.u8(self.trailing_digit_and_tier)?;
        w.u8(self.tiers_and_register)?;
        w.u32_le(self.start_time)?;
        w.u16_le(self.duration_minutes)?;
        w.u32_le(self.price)?;
        w.u8(self.price_ratio)?;
        w.u32_le(self.generation_price)?;
        w.u8(self.generation_price_ratio)?;
        w.u32_le(self.alternate_cost_delivered)?;
        w.u8(self.alternate_cost_unit)?;
        w.u8(self.alternate_cost_trailing_digit)?;
        w.u8(self.number_of_block_thresholds)?;
        w.u8(self.price_control)?;
        for v in [
            self.number_of_generation_tiers,
            self.generation_tier,
            self.extended_number_of_price_tiers,
            self.extended_price_tier,
            self.extended_register_tier,
        ] {
            match v {
                Some(v) => w.u8(v)?,
                None => break,
            }
        }
        Ok(())
    }

    /// Number of digits right of the decimal point in `price`.
    pub const fn trailing_digits(&self) -> u8 {
        self.trailing_digit_and_tier >> 4
    }

    /// Current price tier (with the extended field, D.4.2.4.1.1).
    pub fn price_tier(&self) -> u8 {
        let t = self.trailing_digit_and_tier & 0x0F;
        match (t, self.extended_price_tier) {
            (0xF, Some(x)) if x != 0 => t.saturating_add(x),
            _ => t,
        }
    }

    /// Whether the client must answer with a Price Acknowledgement.
    pub const fn acknowledgement_required(&self) -> bool {
        self.price_control & price_control::ACKNOWLEDGEMENT_REQUIRED != 0
    }

    /// End time, `None` for "until changed".
    pub const fn end_time(&self, now: u32) -> Option<u32> {
        if self.duration_minutes == DURATION_UNTIL_CHANGED {
            None
        } else {
            let start = if self.start_time == 0 {
                now
            } else {
                self.start_time
            };
            Some(start.saturating_add((self.duration_minutes as u32).saturating_mul(60)))
        }
    }
}

/// Get Current Price payload (Figure D-58).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetCurrentPrice {
    /// Requestor Rx On When Idle.
    pub rx_on_when_idle: bool,
}

impl GetCurrentPrice {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [o] => Some(GetCurrentPrice {
                rx_on_when_idle: o & 0x01 != 0,
            }),
            _ => None,
        }
    }

    /// The one-octet payload.
    pub const fn encode(self) -> [u8; 1] {
        [self.rx_on_when_idle as u8]
    }
}

/// Get Scheduled Prices payload (Figure D-60).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetScheduledPrices {
    /// Minimum end time of the prices to send (0 = now).
    pub start_time: u32,
    /// Maximum number of prices (0 = no limit).
    pub number_of_events: u8,
}

impl GetScheduledPrices {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(GetScheduledPrices {
            start_time: r.u32_le()?,
            number_of_events: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.start_time)?;
        w.u8(self.number_of_events)
    }
}

/// Price Acknowledgement payload (Figure D-61).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PriceAcknowledgement {
    /// Provider ID.
    pub provider_id: u32,
    /// Issuer Event ID.
    pub issuer_event_id: u32,
    /// Time of the acknowledgement.
    pub price_ack_time: u32,
    /// The Price Control of the acknowledged price.
    pub control: u8,
}

impl PriceAcknowledgement {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(PriceAcknowledgement {
            provider_id: r.u32_le()?,
            issuer_event_id: r.u32_le()?,
            price_ack_time: r.u32_le()?,
            control: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.price_ack_time)?;
        w.u8(self.control)
    }
}

/// A price held by a client.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct StoredPrice {
    /// Provider ID.
    pub provider_id: u32,
    /// Issuer Event ID.
    pub issuer_event_id: u32,
    /// Effective start (UTC seconds).
    pub start: u32,
    /// End, `None` for "until changed".
    pub end: Option<u32>,
    /// Price.
    pub price: u32,
    /// Trailing digit and tier octet.
    pub trailing_digit_and_tier: u8,
    /// Currency.
    pub currency: u16,
    /// Unit of measure.
    pub unit_of_measure: u8,
    /// Price control.
    pub price_control: u8,
}

/// Client-side price table (D.4.2.4.1): at least the current and the
/// next price, newer overlapping prices replacing older ones.
#[derive(Clone, Debug, Default)]
pub struct PriceTable<const N: usize> {
    prices: Vec<StoredPrice, N>,
}

impl<const N: usize> PriceTable<N> {
    /// Empty table.
    pub const fn new() -> Self {
        PriceTable { prices: Vec::new() }
    }

    /// Stored prices, ordered by start time.
    pub fn prices(&self) -> &[StoredPrice] {
        &self.prices
    }

    /// Handles a Publish Price: returns the acknowledgement to send
    /// when one is required, or `None`. A price older than an
    /// overlapping stored one is ignored.
    pub fn on_publish(&mut self, p: &PublishPrice<'_>, now: u32) -> Option<PriceAcknowledgement> {
        let start = if p.start_time == 0 { now } else { p.start_time };
        let end = p.end_time(now);
        let ack = p
            .acknowledgement_required()
            .then_some(PriceAcknowledgement {
                provider_id: p.provider_id,
                issuer_event_id: p.issuer_event_id,
                price_ack_time: now,
                control: p.price_control,
            });
        if self
            .prices
            .iter()
            .any(|s| s.issuer_event_id > p.issuer_event_id && overlaps(s.start, s.end, start, end))
        {
            return ack;
        }
        // Newer overlapping prices win; an active price that the new one
        // cuts into is kept and ends when the new one begins.
        let mut i = 0;
        while i < self.prices.len() {
            let s = self.prices[i];
            if s.issuer_event_id == p.issuer_event_id || overlaps(s.start, s.end, start, end) {
                if s.issuer_event_id != p.issuer_event_id && s.start <= now && start > now {
                    self.prices[i].end = Some(start);
                    i += 1;
                } else {
                    self.prices.remove(i);
                }
            } else {
                i += 1;
            }
        }
        let stored = StoredPrice {
            provider_id: p.provider_id,
            issuer_event_id: p.issuer_event_id,
            start,
            end,
            price: p.price,
            trailing_digit_and_tier: p.trailing_digit_and_tier,
            currency: p.currency,
            unit_of_measure: p.unit_of_measure,
            price_control: p.price_control,
        };
        let pos = self
            .prices
            .iter()
            .position(|s| s.start > start)
            .unwrap_or(self.prices.len());
        if self.prices.insert(pos, stored).is_err() {
            // Full: drop the price furthest in the future.
            self.prices.pop();
            let _ = self.prices.insert(pos.min(self.prices.len()), stored);
        }
        ack
    }

    /// Drops expired prices; returns true when something changed.
    pub fn poll(&mut self, now: u32) -> bool {
        let before = self.prices.len();
        self.prices.retain(|s| s.end.is_none_or(|e| now < e));
        self.prices.len() != before
    }

    /// The price in effect at `now`.
    pub fn current(&self, now: u32) -> Option<&StoredPrice> {
        self.prices
            .iter()
            .filter(|s| s.start <= now && s.end.is_none_or(|e| now < e))
            .max_by_key(|s| s.issuer_event_id)
    }

    /// The next price to become active after `now`.
    pub fn next(&self, now: u32) -> Option<&StoredPrice> {
        self.prices.iter().find(|s| s.start > now)
    }
}

const fn overlaps(a_start: u32, a_end: Option<u32>, b_start: u32, b_end: Option<u32>) -> bool {
    let a_before_b_ends = match b_end {
        Some(e) => a_start < e,
        None => true,
    };
    let b_before_a_ends = match a_end {
        Some(e) => b_start < e,
        None => true,
    };
    a_before_b_ends && b_before_a_ends
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_price_codec_and_table() {
        let mut p = PublishPrice::new(0x11, b"Peak", 100, 5000, 6000, 60, 1234);
        p.currency = 840;
        p.trailing_digit_and_tier = 0x32;
        p.price_control = price_control::ACKNOWLEDGEMENT_REQUIRED;
        p.number_of_generation_tiers = Some(2);
        p.generation_tier = Some(1);
        let mut buf = [0u8; 96];
        let mut w = Writer::new(&mut buf);
        p.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(
            n,
            4 + 1 + 4 + 4 + 4 + 1 + 2 + 1 + 1 + 4 + 2 + 4 + 1 + 4 + 1 + 4 + 1 + 1 + 1 + 1 + 2
        );
        assert_eq!(PublishPrice::parse(&buf[..n]).unwrap(), p);
        assert_eq!(p.trailing_digits(), 3);
        assert_eq!(p.price_tier(), 2);
        // An SE 1.0 frame ending after Price.
        let short = PublishPrice::parse(&buf[..32]).unwrap();
        assert_eq!(short.price, 1234);
        assert_eq!(short.price_ratio, RATIO_UNUSED);
        assert_eq!(short.price_control, 0);
        // Extended tier: 0xF + extended.
        let mut x = p;
        x.trailing_digit_and_tier = 0x2F;
        x.extended_price_tier = Some(3);
        assert_eq!(x.price_tier(), 18);

        let mut t: PriceTable<4> = PriceTable::new();
        let ack = t.on_publish(&p, 5000).unwrap();
        assert_eq!(ack.issuer_event_id, 100);
        assert_eq!(ack.control, price_control::ACKNOWLEDGEMENT_REQUIRED);
        assert!(t.current(5000).is_none());
        assert_eq!(t.next(5000).unwrap().issuer_event_id, 100);
        assert_eq!(t.current(6100).unwrap().price, 1234);
        // A newer price overlapping the end of the active one: the active
        // one now ends when the new one starts.
        let mut q = PublishPrice::new(0x11, b"Off", 101, 7000, 8000, DURATION_UNTIL_CHANGED, 500);
        q.price_control = 0;
        assert!(t.on_publish(&q, 7000).is_none());
        assert_eq!(t.prices().len(), 2);
        assert_eq!(t.prices()[0].end, Some(8000));
        assert_eq!(t.prices()[1].end, None);
        // An older overlapping price is ignored.
        let old = PublishPrice::new(0x11, b"Old", 50, 7000, 8500, 10, 1);
        assert!(t.on_publish(&old, 7000).is_none());
        assert_eq!(t.prices().len(), 2);
        assert!(t.poll(8000));
        assert_eq!(t.current(9000).unwrap().price, 500);
        // A "now" price replaces the current one.
        let now_price = PublishPrice::new(0x11, b"Now", 102, 9000, 0, 30, 77);
        assert!(t.on_publish(&now_price, 9000).is_none());
        assert_eq!(t.prices().len(), 1);
        assert_eq!(t.current(9000).unwrap().price, 77);
        assert_eq!(t.prices()[0].end, Some(9000 + 1800));
        // Client command codecs.
        assert_eq!(
            GetCurrentPrice::parse(
                &GetCurrentPrice {
                    rx_on_when_idle: true
                }
                .encode()
            ),
            Some(GetCurrentPrice {
                rx_on_when_idle: true
            })
        );
        let g = GetScheduledPrices {
            start_time: 0,
            number_of_events: 2,
        };
        let mut w = Writer::new(&mut buf);
        g.encode(&mut w).unwrap();
        assert_eq!(GetScheduledPrices::parse(&buf[..5]).unwrap(), g);
        let mut w = Writer::new(&mut buf);
        ack.encode(&mut w).unwrap();
        assert_eq!(PriceAcknowledgement::parse(&buf[..13]).unwrap(), ack);
    }
}
