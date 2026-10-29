//! Sizes of the Lite device and its parts on the build target, for
//! footprint reports and regression checks (`examples/lite-probe`,
//! `tests/footprint.rs`, `docs/lite.md`). Each entry is `size_of` of a
//! type; parts are listed below the whole they belong to and are not to
//! be added to it again.

use core::mem::size_of;

use panweave_runtime::{
    ProfileAps, ProfileEndpoint, ProfileNwk, ProfileZcl, ProfileZdo, SleepySensor, StackEvent,
};
use panweave_security::cipher::BlockCipher;
use panweave_storage::Storage;
use panweave_types::CryptoRng;

use crate::{CLUSTER_ATTRIBUTES, ENDPOINT_CLUSTERS, ENDPOINTS, LiteDevice, LiteStack};

/// One measured type: name, depth in the tree (0 = the device) and size
/// in octets.
pub type Entry = (&'static str, u8, usize);

/// The size table of a [`LiteDevice`] over cipher `C`, generator `R` and
/// storage `S`.
pub fn components<C: BlockCipher, R: CryptoRng, S: Storage>() -> [Entry; 14] {
    type P = SleepySensor;
    [
        ("LiteDevice", 0, size_of::<LiteDevice<C, R, S>>()),
        ("LiteStack", 1, size_of::<LiteStack<C, R, S>>()),
        (
            "MAC",
            2,
            size_of::<panweave_mac::service::MacService<panweave_mac::service::EndDeviceMac>>(),
        ),
        ("NWK", 2, size_of::<ProfileNwk<C, R, P>>()),
        ("APS", 2, size_of::<ProfileAps<C, P>>()),
        ("ZDO", 2, size_of::<ProfileZdo<P>>()),
        (
            "ZCL",
            2,
            size_of::<ProfileZcl<P, ENDPOINTS, ENDPOINT_CLUSTERS, CLUSTER_ATTRIBUTES>>(),
        ),
        (
            "ZCL endpoint",
            3,
            size_of::<ProfileEndpoint<P, ENDPOINT_CLUSTERS, CLUSTER_ATTRIBUTES>>(),
        ),
        (
            "ZCL cluster",
            4,
            size_of::<panweave_runtime::ProfileCluster<P, CLUSTER_ATTRIBUTES>>(),
        ),
        (
            "ZCL attribute",
            5,
            size_of::<panweave_zcl::attribute::Attribute>(),
        ),
        ("Storage", 2, size_of::<S>()),
        ("Block cipher", 3, size_of::<C>()),
        ("StackEvent", 3, size_of::<StackEvent>()),
        ("BDB", 1, size_of::<panweave_bdb::Bdb>()),
    ]
}
