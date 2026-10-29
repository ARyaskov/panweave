# panweave-lite

The Panweave Zigbee stack dimensioned for battery IAS Zone sensors (door
/ window contacts, water leak sensors) on microcontrollers with 32 KiB of
RAM: the same protocol code as the full stack with the `SleepySensor`
profile, an IAS Zone sensor endpoint, alarm delivery tracking, enrolment
persistence and a sleep planner.

```rust,ignore
use panweave_lite::{LiteConfig, LiteDevice, SensorKind};
use panweave_lite::sensor::Inputs;

static mut DEVICE: core::mem::MaybeUninit<Sensor> = core::mem::MaybeUninit::uninit();

let cfg = LiteConfig::new(ieee, SensorKind::WaterLeak).install_code_key(key);
let dev = LiteDevice::new_in(slot, &cfg, trng, flash_store)?;
dev.initialize(board.read_inputs())?;
if !dev.bdb.is_on_network() {
    dev.start_commissioning()?;
}
loop {
    while let Some(a) = dev.next_radio_action() { radio.perform(a); }
    while let Some(e) = dev.next_event() { app.handle(e); }
    let plan = dev.sleep_plan(rtc.now());
    platform.sleep(&plan);
    dev.poll(rtc.now());
}
```

Measured footprint, method and status (no hardware run yet): see
[`docs/lite.md`](../docs/lite.md).
