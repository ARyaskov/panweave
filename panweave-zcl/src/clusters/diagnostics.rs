//! Diagnostics cluster (ZCL8 §3.15): the hardware and stack / network
//! counters of Tables 3-130 and 3-131. The attributes are read-only
//! snapshots the host refreshes from its stack statistics
//! (`Counters` → `update`); a runtime feeds the counters it maintains.

use panweave_types::ClusterId;

use crate::attribute::{Access, AttributeDef};
use crate::cluster::{ClusterDef, ClusterInstance, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0b05);

// Hardware Information (Table 3-130).
/// `NumberOfResets` (uint16).
pub const NUMBER_OF_RESETS: AttributeDef = AttributeDef::new(0x0000, DataType::Uint(2), Access::RO);
/// `PersistentMemoryWrites` (uint16).
pub const PERSISTENT_MEMORY_WRITES: AttributeDef =
    AttributeDef::new(0x0001, DataType::Uint(2), Access::RO);
// Stack / Network Information (Table 3-131).
/// `MacRxBcast` (uint32).
pub const MAC_RX_BCAST: AttributeDef = AttributeDef::new(0x0100, DataType::Uint(4), Access::RO);
/// `MacTxBcast` (uint32).
pub const MAC_TX_BCAST: AttributeDef = AttributeDef::new(0x0101, DataType::Uint(4), Access::RO);
/// `MacRxUcast` (uint32).
pub const MAC_RX_UCAST: AttributeDef = AttributeDef::new(0x0102, DataType::Uint(4), Access::RO);
/// `MacTxUcast` (uint32).
pub const MAC_TX_UCAST: AttributeDef = AttributeDef::new(0x0103, DataType::Uint(4), Access::RO);
/// `MacTxUcastRetry` (uint16).
pub const MAC_TX_UCAST_RETRY: AttributeDef =
    AttributeDef::new(0x0104, DataType::Uint(2), Access::RO);
/// `MacTxUcastFail` (uint16).
pub const MAC_TX_UCAST_FAIL: AttributeDef =
    AttributeDef::new(0x0105, DataType::Uint(2), Access::RO);
/// `APSRxBcast` (uint16).
pub const APS_RX_BCAST: AttributeDef = AttributeDef::new(0x0106, DataType::Uint(2), Access::RO);
/// `APSTxBcast` (uint16).
pub const APS_TX_BCAST: AttributeDef = AttributeDef::new(0x0107, DataType::Uint(2), Access::RO);
/// `APSRxUcast` (uint16).
pub const APS_RX_UCAST: AttributeDef = AttributeDef::new(0x0108, DataType::Uint(2), Access::RO);
/// `APSTxUcastSuccess` (uint16).
pub const APS_TX_UCAST_SUCCESS: AttributeDef =
    AttributeDef::new(0x0109, DataType::Uint(2), Access::RO);
/// `APSTxUcastRetry` (uint16).
pub const APS_TX_UCAST_RETRY: AttributeDef =
    AttributeDef::new(0x010a, DataType::Uint(2), Access::RO);
/// `APSTxUcastFail` (uint16).
pub const APS_TX_UCAST_FAIL: AttributeDef =
    AttributeDef::new(0x010b, DataType::Uint(2), Access::RO);
/// `RouteDiscInitiated` (uint16).
pub const ROUTE_DISC_INITIATED: AttributeDef =
    AttributeDef::new(0x010c, DataType::Uint(2), Access::RO);
/// `NeighborAdded` (uint16).
pub const NEIGHBOR_ADDED: AttributeDef = AttributeDef::new(0x010d, DataType::Uint(2), Access::RO);
/// `NeighborRemoved` (uint16).
pub const NEIGHBOR_REMOVED: AttributeDef = AttributeDef::new(0x010e, DataType::Uint(2), Access::RO);
/// `NeighborStale` (uint16).
pub const NEIGHBOR_STALE: AttributeDef = AttributeDef::new(0x010f, DataType::Uint(2), Access::RO);
/// `JoinIndication` (uint16).
pub const JOIN_INDICATION: AttributeDef = AttributeDef::new(0x0110, DataType::Uint(2), Access::RO);
/// `ChildMoved` (uint16).
pub const CHILD_MOVED: AttributeDef = AttributeDef::new(0x0111, DataType::Uint(2), Access::RO);
/// `NWKFCFailure` (uint16).
pub const NWK_FC_FAILURE: AttributeDef = AttributeDef::new(0x0112, DataType::Uint(2), Access::RO);
/// `APSFCFailure` (uint16).
pub const APS_FC_FAILURE: AttributeDef = AttributeDef::new(0x0113, DataType::Uint(2), Access::RO);
/// `APSUnauthorizedKey` (uint16).
pub const APS_UNAUTHORIZED_KEY: AttributeDef =
    AttributeDef::new(0x0114, DataType::Uint(2), Access::RO);
/// `NWKDecryptFailures` (uint16).
pub const NWK_DECRYPT_FAILURES: AttributeDef =
    AttributeDef::new(0x0115, DataType::Uint(2), Access::RO);
/// `APSDecryptFailures` (uint16).
pub const APS_DECRYPT_FAILURES: AttributeDef =
    AttributeDef::new(0x0116, DataType::Uint(2), Access::RO);
/// `PacketBufferAllocateFailures` (uint16).
pub const PACKET_BUFFER_ALLOCATE_FAILURES: AttributeDef =
    AttributeDef::new(0x0117, DataType::Uint(2), Access::RO);
/// `RelayedUcast` (uint16).
pub const RELAYED_UCAST: AttributeDef = AttributeDef::new(0x0118, DataType::Uint(2), Access::RO);
/// `PhyToMACQueueLimitReached` (uint16).
pub const PHY_TO_MAC_QUEUE_LIMIT_REACHED: AttributeDef =
    AttributeDef::new(0x0119, DataType::Uint(2), Access::RO);
/// `PacketValidateDropCount` (uint16).
pub const PACKET_VALIDATE_DROP_COUNT: AttributeDef =
    AttributeDef::new(0x011a, DataType::Uint(2), Access::RO);
/// `AverageMACRetryPerAPSMessageSent` (uint16).
pub const AVERAGE_MAC_RETRY_PER_APS_MESSAGE_SENT: AttributeDef =
    AttributeDef::new(0x011b, DataType::Uint(2), Access::RO);
/// `LastMessageLQI` (uint8).
pub const LAST_MESSAGE_LQI: AttributeDef = AttributeDef::new(0x011c, DataType::Uint(1), Access::RO);
/// `LastMessageRSSI` (int8).
pub const LAST_MESSAGE_RSSI: AttributeDef = AttributeDef::new(0x011d, DataType::Int(1), Access::RO);

/// Cluster definition (attribute-only).
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[],
    generated: &[],
};

/// The counters a stack can supply (§3.15.2.2). Counters wrap at the
/// attribute width; a `None` leaves the attribute untouched.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Counters {
    /// Resets since manufacture.
    pub resets: Option<u16>,
    /// Persistent memory writes.
    pub persistent_writes: Option<u16>,
    /// MAC broadcast receptions.
    pub mac_rx_bcast: Option<u32>,
    /// MAC broadcast transmissions.
    pub mac_tx_bcast: Option<u32>,
    /// MAC unicast receptions.
    pub mac_rx_ucast: Option<u32>,
    /// MAC unicast transmissions.
    pub mac_tx_ucast: Option<u32>,
    /// MAC unicast retransmissions.
    pub mac_tx_ucast_retry: Option<u16>,
    /// MAC unicast transmission failures.
    pub mac_tx_ucast_fail: Option<u16>,
    /// APS broadcast receptions.
    pub aps_rx_bcast: Option<u16>,
    /// APS broadcast transmissions.
    pub aps_tx_bcast: Option<u16>,
    /// APS unicast receptions.
    pub aps_rx_ucast: Option<u16>,
    /// APS unicast transmissions confirmed.
    pub aps_tx_ucast_success: Option<u16>,
    /// APS unicast retransmissions.
    pub aps_tx_ucast_retry: Option<u16>,
    /// APS unicast transmissions that failed after all retries.
    pub aps_tx_ucast_fail: Option<u16>,
    /// Route discoveries initiated.
    pub route_disc_initiated: Option<u16>,
    /// Neighbor table entries added.
    pub neighbor_added: Option<u16>,
    /// Neighbor table entries removed.
    pub neighbor_removed: Option<u16>,
    /// Neighbor table entries gone stale.
    pub neighbor_stale: Option<u16>,
    /// Join indications.
    pub join_indication: Option<u16>,
    /// Children that moved to another parent.
    pub child_moved: Option<u16>,
    /// NWK frame counter failures (replays).
    pub nwk_fc_failure: Option<u16>,
    /// APS frame counter failures.
    pub aps_fc_failure: Option<u16>,
    /// Frames secured with an unauthorized key.
    pub aps_unauthorized_key: Option<u16>,
    /// NWK decryption failures.
    pub nwk_decrypt_failures: Option<u16>,
    /// APS decryption failures.
    pub aps_decrypt_failures: Option<u16>,
    /// Buffer allocation failures (queue overflows).
    pub packet_buffer_allocate_failures: Option<u16>,
    /// Unicasts relayed.
    pub relayed_ucast: Option<u16>,
    /// Frames dropped by validation.
    pub packet_validate_drop_count: Option<u16>,
    /// Frames refused because the MAC transmit queue was full.
    pub phy_to_mac_queue_limit_reached: Option<u16>,
    /// Average MAC retries per APS message sent.
    pub average_mac_retry_per_aps_message_sent: Option<u16>,
    /// LQI of the last received message.
    pub last_lqi: Option<u8>,
    /// RSSI of the last received message.
    pub last_rssi: Option<i8>,
}

/// The attributes instantiated by [`server`], in identifier order.
pub const SERVER_ATTRIBUTES: &[AttributeDef] = &[
    NUMBER_OF_RESETS,
    PERSISTENT_MEMORY_WRITES,
    MAC_RX_BCAST,
    MAC_TX_BCAST,
    MAC_RX_UCAST,
    MAC_TX_UCAST,
    MAC_TX_UCAST_RETRY,
    MAC_TX_UCAST_FAIL,
    APS_RX_BCAST,
    APS_TX_BCAST,
    APS_RX_UCAST,
    APS_TX_UCAST_SUCCESS,
    APS_TX_UCAST_RETRY,
    APS_TX_UCAST_FAIL,
    ROUTE_DISC_INITIATED,
    NEIGHBOR_ADDED,
    NEIGHBOR_REMOVED,
    NEIGHBOR_STALE,
    JOIN_INDICATION,
    CHILD_MOVED,
    NWK_FC_FAILURE,
    APS_FC_FAILURE,
    APS_UNAUTHORIZED_KEY,
    NWK_DECRYPT_FAILURES,
    APS_DECRYPT_FAILURES,
    PACKET_BUFFER_ALLOCATE_FAILURES,
    RELAYED_UCAST,
    PHY_TO_MAC_QUEUE_LIMIT_REACHED,
    PACKET_VALIDATE_DROP_COUNT,
    AVERAGE_MAC_RETRY_PER_APS_MESSAGE_SENT,
    LAST_MESSAGE_LQI,
    LAST_MESSAGE_RSSI,
];

/// Builds a server with the counters a Panweave stack maintains.
pub fn server<const A: usize>() -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    for a in SERVER_ATTRIBUTES {
        let v = match a.ty {
            DataType::Int(w) => Value::Int { width: w, value: 0 },
            DataType::Uint(w) => Value::Uint { width: w, value: 0 },
            _ => Value::Uint { width: 2, value: 0 },
        };
        c.add_attribute(*a, &v)?;
    }
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF.mirrored(), Role::Client)
}

fn set_u16<const A: usize>(c: &mut ClusterInstance<A>, def: AttributeDef, v: Option<u16>) {
    if let Some(v) = v {
        c.set_u16(def.id, v);
    }
}

/// Writes the supplied counters into the attributes.
pub fn update<const A: usize>(c: &mut ClusterInstance<A>, k: &Counters) {
    set_u16(c, NUMBER_OF_RESETS, k.resets);
    set_u16(c, PERSISTENT_MEMORY_WRITES, k.persistent_writes);
    for (def, v) in [
        (MAC_RX_BCAST, k.mac_rx_bcast),
        (MAC_TX_BCAST, k.mac_tx_bcast),
        (MAC_RX_UCAST, k.mac_rx_ucast),
        (MAC_TX_UCAST, k.mac_tx_ucast),
    ] {
        if let Some(v) = v {
            c.set(
                def.id,
                &Value::Uint {
                    width: 4,
                    value: u64::from(v),
                },
            );
        }
    }
    set_u16(c, MAC_TX_UCAST_RETRY, k.mac_tx_ucast_retry);
    set_u16(c, MAC_TX_UCAST_FAIL, k.mac_tx_ucast_fail);
    set_u16(c, APS_RX_BCAST, k.aps_rx_bcast);
    set_u16(c, APS_TX_BCAST, k.aps_tx_bcast);
    set_u16(c, APS_RX_UCAST, k.aps_rx_ucast);
    set_u16(c, APS_TX_UCAST_SUCCESS, k.aps_tx_ucast_success);
    set_u16(c, APS_TX_UCAST_RETRY, k.aps_tx_ucast_retry);
    set_u16(c, APS_TX_UCAST_FAIL, k.aps_tx_ucast_fail);
    set_u16(c, ROUTE_DISC_INITIATED, k.route_disc_initiated);
    set_u16(c, NEIGHBOR_ADDED, k.neighbor_added);
    set_u16(c, NEIGHBOR_REMOVED, k.neighbor_removed);
    set_u16(c, NEIGHBOR_STALE, k.neighbor_stale);
    set_u16(c, JOIN_INDICATION, k.join_indication);
    set_u16(c, CHILD_MOVED, k.child_moved);
    set_u16(
        c,
        PHY_TO_MAC_QUEUE_LIMIT_REACHED,
        k.phy_to_mac_queue_limit_reached,
    );
    set_u16(
        c,
        AVERAGE_MAC_RETRY_PER_APS_MESSAGE_SENT,
        k.average_mac_retry_per_aps_message_sent,
    );
    set_u16(c, NWK_FC_FAILURE, k.nwk_fc_failure);
    set_u16(c, APS_FC_FAILURE, k.aps_fc_failure);
    set_u16(c, APS_UNAUTHORIZED_KEY, k.aps_unauthorized_key);
    set_u16(c, NWK_DECRYPT_FAILURES, k.nwk_decrypt_failures);
    set_u16(c, APS_DECRYPT_FAILURES, k.aps_decrypt_failures);
    set_u16(
        c,
        PACKET_BUFFER_ALLOCATE_FAILURES,
        k.packet_buffer_allocate_failures,
    );
    set_u16(c, RELAYED_UCAST, k.relayed_ucast);
    set_u16(c, PACKET_VALIDATE_DROP_COUNT, k.packet_validate_drop_count);
    if let Some(v) = k.last_lqi {
        c.set_u8(LAST_MESSAGE_LQI.id, v);
    }
    if let Some(v) = k.last_rssi {
        c.set(
            LAST_MESSAGE_RSSI.id,
            &Value::Int {
                width: 1,
                value: i64::from(v),
            },
        );
    }
}

/// Truncates a wider counter to the attribute width (the counters wrap,
/// §3.15.2.2.2).
pub const fn wrap16(v: u32) -> u16 {
    (v & 0xffff) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_land_in_attributes() {
        let mut c: ClusterInstance<36> = server().unwrap();
        update(
            &mut c,
            &Counters {
                mac_tx_ucast: Some(70_000),
                aps_tx_ucast_fail: Some(3),
                nwk_decrypt_failures: Some(wrap16(0x1_0005)),
                last_rssi: Some(-40),
                last_lqi: Some(200),
                ..Counters::default()
            },
        );
        assert_eq!(c.u64(MAC_TX_UCAST.id), Some(70_000));
        assert_eq!(c.u16(APS_TX_UCAST_FAIL.id), Some(3));
        assert_eq!(c.u16(NWK_DECRYPT_FAILURES.id), Some(5));
        assert_eq!(c.u16(RELAYED_UCAST.id), Some(0));
        assert_eq!(c.i16(LAST_MESSAGE_RSSI.id), Some(-40));
        assert_eq!(c.u8(LAST_MESSAGE_LQI.id), Some(200));
    }
}
