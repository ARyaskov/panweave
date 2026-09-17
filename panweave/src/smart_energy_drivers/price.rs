//! Price cluster drivers (SE 1.4a Annex D.4, the Publish Price core):
//! the client keeping the current and scheduled prices and acknowledging
//! them, and the server (ESI) publishing prices and answering Get
//! Current Price / Get Scheduled Prices.

use heapless::Vec;
use panweave_aps::layer::Destination;
use panweave_runtime::{Stack, StackEvent};
use panweave_security::cipher::BlockCipher;
use panweave_smart_energy::clusters::price::{
    self, GetCurrentPrice, GetScheduledPrices, PriceAcknowledgement, PriceSchedule, PriceTable,
    PublishPrice, PublishedPrice, StoredPrice,
};
use panweave_storage::Storage;
use panweave_types::time::Instant;
use panweave_types::{CryptoRng, Endpoint, ShortAddress};
use panweave_zcl::ZclStatus;
use panweave_zcl::frame::Direction;

use super::{UtcClock, command_for, default_response, reply, send, utc_now};

/// Largest Publish Price frame.
const PUBLISH_LEN: usize = 64;

/// What a [`PriceClient`] reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PriceEvent {
    /// A price was published (stored, and acknowledged when required);
    /// see [`PriceClient::table`] for the current and next prices.
    Published {
        /// Provider ID.
        provider_id: u32,
        /// Issuer Event ID.
        issuer_event_id: u32,
        /// It replaced or extended the table (false: older than an
        /// overlapping price, ignored).
        stored: bool,
    },
    /// Prices expired from the table.
    Expired,
}

/// The client driver on `endpoint`, holding up to `N` prices.
pub struct PriceClient<const N: usize = 8> {
    endpoint: Endpoint,
    /// The prices.
    pub table: PriceTable<N>,
    /// UTC reference when the endpoint has no Time server.
    pub clock: UtcClock,
}

impl<const N: usize> PriceClient<N> {
    /// A client with no prices.
    pub const fn new(endpoint: Endpoint) -> Self {
        PriceClient {
            endpoint,
            table: PriceTable::new(),
            clock: UtcClock::new(),
        }
    }

    /// Feeds a stack event.
    pub fn on_event<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        event: &StackEvent,
    ) -> Option<PriceEvent> {
        let (origin, payload) = command_for(event, self.endpoint, price::ID, Direction::ToClient)?;
        let origin = *origin;
        let now = utc_now(stack, self.endpoint, &self.clock);
        match origin.header.command {
            price::CMD_PUBLISH_PRICE => {
                let Ok(p) = PublishPrice::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                let before = self.table.prices().len();
                let known = self
                    .table
                    .prices()
                    .iter()
                    .any(|s| s.issuer_event_id == p.issuer_event_id);
                let ack = self.table.on_publish(&p, now);
                let stored = known
                    || self.table.prices().len() != before
                    || self
                        .table
                        .prices()
                        .iter()
                        .any(|s| s.issuer_event_id == p.issuer_event_id);
                match ack {
                    Some(a) => {
                        let mut buf = [0u8; 13];
                        let mut w = panweave_codec::Writer::new(&mut buf);
                        if a.encode(&mut w).is_ok() {
                            reply(stack, &origin, price::CMD_PRICE_ACKNOWLEDGEMENT, &buf);
                        }
                    }
                    None => default_response(stack, &origin, ZclStatus::Success),
                }
                Some(PriceEvent::Published {
                    provider_id: p.provider_id,
                    issuer_event_id: p.issuer_event_id,
                    stored,
                })
            }
            _ => {
                default_response(stack, &origin, ZclStatus::UnsupportedClusterCommand);
                None
            }
        }
    }

    /// Drops expired prices.
    pub fn poll<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &Stack<C, R, S>,
        _now: Instant,
    ) -> Option<PriceEvent> {
        let now = utc_now(stack, self.endpoint, &self.clock);
        self.table.poll(now).then_some(PriceEvent::Expired)
    }

    /// The price in effect now.
    pub fn current<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &Stack<C, R, S>,
    ) -> Option<StoredPrice> {
        let now = utc_now(stack, self.endpoint, &self.clock);
        self.table.current(now).copied()
    }

    /// Asks `server` for the current price (Get Current Price).
    pub fn request_current_price<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        server: Destination,
    ) -> bool {
        let rx_on_when_idle = !stack.config.sleepy;
        send(
            stack,
            self.endpoint,
            server,
            price::ID,
            price::CMD_GET_CURRENT_PRICE,
            Direction::ToServer,
            &GetCurrentPrice { rx_on_when_idle }.encode(),
        )
    }

    /// Asks `server` for its scheduled prices (Get Scheduled Prices).
    pub fn request_scheduled_prices<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        server: Destination,
        req: &GetScheduledPrices,
    ) -> bool {
        let mut buf = [0u8; 5];
        let mut w = panweave_codec::Writer::new(&mut buf);
        if req.encode(&mut w).is_err() {
            return false;
        }
        send(
            stack,
            self.endpoint,
            server,
            price::ID,
            price::CMD_GET_SCHEDULED_PRICES,
            Direction::ToServer,
            &buf,
        )
    }
}

/// What a [`PriceServer`] reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PriceServerEvent {
    /// A client acknowledged a price.
    Acknowledged {
        /// The client.
        client: ShortAddress,
        /// The acknowledgement.
        ack: PriceAcknowledgement,
    },
    /// A client asked for the current price or the scheduled ones and
    /// got `count` Publish Prices (NOT_FOUND when zero).
    Requested {
        /// The client.
        client: ShortAddress,
        /// Prices sent.
        count: usize,
    },
}

/// The server driver on `endpoint`, holding up to `N` prices.
pub struct PriceServer<const N: usize = 8> {
    endpoint: Endpoint,
    /// The published prices.
    pub schedule: PriceSchedule<N>,
    /// UTC reference when the endpoint has no Time server.
    pub clock: UtcClock,
}

impl<const N: usize> PriceServer<N> {
    /// A server with no prices.
    pub const fn new(endpoint: Endpoint) -> Self {
        PriceServer {
            endpoint,
            schedule: PriceSchedule::new(),
            clock: UtcClock::new(),
        }
    }

    fn encode(p: &PublishedPrice) -> Option<Vec<u8, PUBLISH_LEN>> {
        let mut out: Vec<u8, PUBLISH_LEN> = Vec::new();
        out.resize(PUBLISH_LEN, 0).ok()?;
        let mut w = panweave_codec::Writer::new(&mut out);
        p.publish().encode(&mut w).ok()?;
        let n = w.position();
        out.truncate(n);
        Some(out)
    }

    /// Publishes `p` (a start time of 0 is resolved to now) to `clients`.
    pub fn publish<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        clients: Destination,
        p: &PublishPrice<'_>,
    ) -> bool {
        let now = utc_now(stack, self.endpoint, &self.clock);
        if !self.schedule.publish(p, now) {
            return false;
        }
        let Some(stored) = self
            .schedule
            .prices()
            .iter()
            .find(|s| s.price.issuer_event_id == p.issuer_event_id)
        else {
            return false;
        };
        let Some(payload) = Self::encode(stored) else {
            return false;
        };
        send(
            stack,
            self.endpoint,
            clients,
            price::ID,
            price::CMD_PUBLISH_PRICE,
            Direction::ToClient,
            &payload,
        )
    }

    /// Feeds a stack event.
    pub fn on_event<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        event: &StackEvent,
    ) -> Option<PriceServerEvent> {
        let (origin, payload) = command_for(event, self.endpoint, price::ID, Direction::ToServer)?;
        let origin = *origin;
        let now = utc_now(stack, self.endpoint, &self.clock);
        self.schedule.expire(now);
        match origin.header.command {
            price::CMD_GET_CURRENT_PRICE => {
                if GetCurrentPrice::parse(payload).is_none() {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                }
                let count = match self.schedule.current(now).and_then(Self::encode) {
                    Some(p) => usize::from(reply(stack, &origin, price::CMD_PUBLISH_PRICE, &p)),
                    None => {
                        default_response(stack, &origin, ZclStatus::NotFound);
                        0
                    }
                };
                Some(PriceServerEvent::Requested {
                    client: origin.src,
                    count,
                })
            }
            price::CMD_GET_SCHEDULED_PRICES => {
                let Ok(req) = GetScheduledPrices::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                let mut frames: Vec<Vec<u8, PUBLISH_LEN>, N> = Vec::new();
                {
                    let mut out: Vec<&PublishedPrice, N> = Vec::new();
                    self.schedule.scheduled(&req, now, &mut out);
                    for p in out {
                        if let Some(f) = Self::encode(p) {
                            let _ = frames.push(f);
                        }
                    }
                }
                if frames.is_empty() {
                    default_response(stack, &origin, ZclStatus::NotFound);
                } else {
                    for f in &frames {
                        reply(stack, &origin, price::CMD_PUBLISH_PRICE, f);
                    }
                }
                Some(PriceServerEvent::Requested {
                    client: origin.src,
                    count: frames.len(),
                })
            }
            price::CMD_PRICE_ACKNOWLEDGEMENT => {
                let Ok(ack) = PriceAcknowledgement::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                let known = self.schedule.on_acknowledgement(origin.src.0, &ack);
                default_response(
                    stack,
                    &origin,
                    if known {
                        ZclStatus::Success
                    } else {
                        ZclStatus::NotFound
                    },
                );
                known.then_some(PriceServerEvent::Acknowledged {
                    client: origin.src,
                    ack,
                })
            }
            _ => {
                default_response(stack, &origin, ZclStatus::UnsupportedClusterCommand);
                None
            }
        }
    }

    /// Drops expired prices.
    pub fn poll<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &Stack<C, R, S>,
        _now: Instant,
    ) {
        let now = utc_now(stack, self.endpoint, &self.clock);
        self.schedule.expire(now);
    }
}
