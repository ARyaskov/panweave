# Specifications

Panweave is implemented from the following normative documents. They are
copyrighted by the Connectivity Standards Alliance and are **not** included in
this repository. Obtain them from the CSA and place them in a directory of
your choice; development scripts accept the path via `PANWEAVE_SPEC_DIR`.

| Short id | Document |
|---|---|
| R23.2 | Zigbee Specification 05-3474-23, Revision 23.2 |
| ZCL8 | Zigbee Cluster Library Specification 07-5123, Revision 8 |
| BDB3.1 | PRO Base Device Behavior Specification 22-65816-030, v3.1 |
| DTL2 | Device Type Library Specification 23-02016, Revision 2 |
| GP1.1.2 | Green Power feature specification, Basic functionality set, 14-0563-19, v1.1.2 |
| ZD1.1 | Zigbee Direct Specification 20-27688-041, Revision 1.1 |
| SE1.4a | Zigbee Smart Energy Standard 1.4a |

The repository contains only paraphrased requirement summaries, section
references, and the wire constants required for interoperability. See
`docs/specification-map.md` for how documents map to crates and
`conformance/` for the requirement inventory.

Panweave is independent of and not endorsed by the Connectivity Standards
Alliance.
