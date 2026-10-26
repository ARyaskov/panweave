//! The hub's application endpoint.

use heapless::Vec;
use panweave_runtime::{ENDPOINT_CLUSTERS, StackCluster, StackEndpoint};
use panweave_types::{ClusterId, DeviceId, Endpoint, ProfileId};
use panweave_zcl::clusters::measurement::{illuminance, occupancy, temperature, water_content};
use panweave_zcl::clusters::{
    color_control, ias_zone, identify, level, on_off, power_configuration,
};
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

/// Combined Interface (DTL §2.x device 0x0007): a client of everything
/// it monitors and controls.
const COMBINED_INTERFACE: DeviceId = DeviceId(0x0007);

/// The hub's endpoint: client instances of the clusters whose reports,
/// responses and notifications the hub consumes (IAS Zone first — the
/// CIE side of enrolment —, then lighting, battery and measurements), as
/// many as the stack's endpoint table holds with one slot left for the
/// Basic server the stack adds itself. Register it with
/// `Node::add_endpoint`; devices bind their clusters to it.
pub fn hub_endpoint(endpoint: Endpoint) -> Option<(SimpleDescriptor, StackEndpoint)> {
    let mut ep = EndpointInstance::new(endpoint, ProfileId::HOME_AUTOMATION);
    let desc = hub_endpoint_into(&mut ep)?;
    Some((desc, ep))
}

/// [`hub_endpoint`] filling `ep` (an empty Home Automation endpoint) in
/// place, for `Node::add_endpoint_with`: the instance is tens of KiB, and
/// building it by value costs copies of it on the caller's stack. Returns
/// its simple descriptor.
pub fn hub_endpoint_into(ep: &mut StackEndpoint) -> Option<SimpleDescriptor> {
    let endpoint = ep.endpoint;
    let candidates: [fn() -> StackCluster; 10] = [
        ias_zone::client,
        on_off::client,
        level::client,
        power_configuration::client,
        temperature::client,
        identify::client,
        color_control::client,
        occupancy::client,
        || water_content::client(water_content::RELATIVE_HUMIDITY),
        illuminance::client,
    ];
    let mut clients: Vec<ClusterId, 16> = Vec::new();
    for make in candidates {
        if ep.clusters.len() + 1 >= ENDPOINT_CLUSTERS {
            break;
        }
        let c = make();
        let id = c.def.id;
        if ep.add_instance(c).is_ok() {
            clients.push(id).ok()?;
        }
    }
    SimpleDescriptor::new(
        endpoint,
        ProfileId::HOME_AUTOMATION,
        COMBINED_INTERFACE,
        0,
        &[ClusterId(0x0000)],
        &clients,
    )
}
