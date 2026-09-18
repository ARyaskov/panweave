# ROM / RAM footprint

Measured on a bare-metal Cortex-M4F (`thumbv7em-none-eabihf`) with the
size probe in `examples/size-probe`: a facade `Node` configured as a
router with an On/Off Light endpoint, software AES, RAM storage
(`MemoryStorage<32, 128>`) and a null radio, built with `opt-level =
"z"`, fat LTO, one codegen unit and `panic = "abort"`. The `Node` is a
`static`, so its size is the `.bss` figure; the main stack, the radio
driver and the application are not included.

| Profile | Features | ROM (`.text` + `.rodata` + vectors) | RAM (`.bss`) |
|---|---|---|---|
| default tables | `crypto-software` | 164.0 KiB | 141.2 KiB |
| `small-tables` | `crypto-software`, `small-tables` | 163.5 KiB | 92.7 KiB |
| default tables, everything | + `green-power`, `dlk`, `direct`, `smart-energy` | 246.2 KiB | 154.4 KiB |
| `small-tables`, everything | + `green-power`, `dlk`, `direct`, `smart-energy`, `small-tables` | 245.3 KiB | 106.0 KiB |

ROM is dominated by the cluster implementations the facade links for
its device library (every server and client in `panweave::endpoints`),
the ZDO, the commissioning machine and, with `dlk`, Curve25519. RAM is
dominated by the ZCL tables.

## Where the RAM goes

`scripts/elf_size.py <elf> --components` reads a table the probe
exports (`PANWEAVE_SIZES`) and prints the size of each component on the
target. Default tables (`Zcl<2, 12, 36>`):

| Component | Bytes | |
|---|---|---|
| `Node` | 144 552 | the whole facade |
| `Stack` | 142 288 | |
| `MacService` | 4 488 | transmit, indirect, action and event queues |
| `Nwk` (`StackNwk`) | 11 312 | 16 neighbours, 16 routes, 4 discoveries, 16 broadcast transactions |
| `Aps` (`StackAps`) | 9 616 | 8 bindings, 8 groups, 8 key pairs, duplicate rejection, pending transmissions, reassembly |
| `Zdo` (`StackZdo`) | 1 912 | 4 endpoints' descriptors |
| `Zcl` (`StackZcl`) | 105 384 | 2 endpoints × 12 clusters |
| `EndpointInstance` | 52 080 | 12 cluster instances |
| `ClusterInstance` | 4 280 | 36 attributes + a 384-octet pool + state |
| `ClusterState` | 944 | the largest variant (the Door Lock user table) |
| `Attribute` | 80 | definition, inline value and default, reporting |
| `MemoryStorage<32, 128>` | 4 880 | |
| event queue | 2 048 | 16 × `StackEvent` |
| `Bdb` | 192 | |

With `small-tables` (`Zcl<2, 8, 24>`) the `Zcl` is 55 784 bytes, an
endpoint 27 280 and a cluster instance 3 320.

### Attribute storage

An attribute entry (`panweave_zcl::attribute::Attribute`, 80 bytes)
holds its definition, its reporting configuration and state, and the
value and factory default of every type of up to eight octets inline
(all integers, enumerations, bitmaps, floats, times and identifiers).
Strings, composites and keys are *wide*: they take
`MAX_ATTRIBUTE_BYTES` (36) octets twice from a 384-octet pool the
cluster's attributes share, so a cluster can hold five wide attributes
(the Basic cluster's two strings take 144 octets; a network key 32).
Adding a sixth wide attribute fails with `INSUFFICIENT_SPACE`, as does a
string longer than 36 octets.

Before this layout an attribute entry carried two full value buffers:
216 bytes, and a default-tables `Node` of 226 KiB.

## Choosing a profile

The table dimensions are fixed by `panweave-runtime`
(`ENDPOINTS`, `ENDPOINT_CLUSTERS`, `CLUSTER_ATTRIBUTES`; the type
aliases `StackZcl`, `StackEndpoint`, `StackCluster`). Every profile
keeps two endpoints: a router is a Green Power proxy, and the proxy
lives on endpoint 242.

| | default | `small-tables` |
|---|---|---|
| clusters per endpoint (the Basic server the stack adds included) | 12 | 8 |
| attributes per cluster | 36 | 24 |
| does not fit | — | Door Lock server (31 attributes), Diagnostics server (33), On/Off Sensor device (11 clusters), a Smart Energy meter with its mirror endpoint |

`small-tables` is a feature of `panweave-runtime` forwarded by
`panweave`. Cargo features are additive: it applies to the whole build,
and a dependency asking for it shrinks every stack in the binary. A
device the profile does not fit fails at `add_endpoint` (or, through
the facade builders, its endpoint validates with a missing cluster);
the facade tests list the device types this affects.

## Levers that remain

Roughly in order of payoff:

* `ClusterState` is an enum of every cluster's server state, so each
  instance pays for the largest variant (the Door Lock's 944 bytes; the
  IAS ACE panel and the Appliance Statistics log are next). Boxing is
  not available without `alloc`; a per-stack arena of the large states
  indexed from the instance would cut ~20 KiB from the default profile.
* The NWK and APS tables (`StackNwk`, `StackAps`) are sized for a
  router with a few children; an end device needs far fewer neighbours
  and routes.
* `MemoryStorage<32, 128>` is the probe's choice; a flash-backed
  `Storage` keeps only its write buffer in RAM.
* `MAX_ATTRIBUTE_BYTES` and `ATTRIBUTE_POOL` are constants; a device
  with long strings (a 64-octet `ProductURL`) needs them raised, a
  device with none could halve the pool.

## Running the probe

```bash
rustup target add thumbv7em-none-eabihf
cd examples/size-probe && cargo build --release [--features small-tables,green-power,dlk,direct,smart-energy]
python ../../scripts/elf_size.py target/thumbv7em-none-eabihf/release/panweave-size-probe --components
```

The probe is its own package (excluded from the workspace) whose
`.cargo/config.toml` selects the target, so build it from its
directory. `elf_size.py` needs no binutils; `arm-none-eabi-size` gives
the same totals. The `footprint` CI job builds the default and the
`small-tables` all-features probes and prints both breakdowns in its
log, so a change's cost shows up in the pull request.
