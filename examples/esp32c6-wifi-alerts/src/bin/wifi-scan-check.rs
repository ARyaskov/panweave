//! **Diagnostic** firmware (not a product image): is Wi-Fi reception on
//! this board worse after IEEE 802.15.4 has used the shared radio?
//!
//! It prints over the USB Serial/JTAG console, which `espflash monitor`
//! shows. Three phases follow, each with three cycles of "create the Wi-Fi
//! controller, scan, drop it", as the hub does for every attempt:
//!
//! * **A**: Wi-Fi only. 802.15.4 has never been started since reset.
//! * **B**: before each cycle, 802.15.4 receives on channel 11 for 3 s and
//!   is dropped, as the hub's driver is before Wi-Fi.
//! * **A2**: Wi-Fi only again, after B (does the effect persist?).
//!
//! Each cycle prints:
//!
//! * the access points a broadcast scan heard (40–80 ms per channel, hidden
//!   ones included), strongest first;
//! * the result of a directed scan for `PANWEAVE_SCAN_SSID`, when set at
//!   build time. Probes name the SSID, so a hidden network answers.
//!
//! Build: `PANWEAVE_SCAN_SSID=MyNet cargo build --release --bin wifi-scan-check`.

#![no_std]
#![no_main]

use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::time::Duration;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use esp_radio::ieee802154::{Config as RadioConfig, Ieee802154};
use esp_radio::wifi::scan::{ScanConfig, ScanTypeConfig};
use esp_radio::wifi::sta::StationConfig;
use esp_radio::wifi::{Config, ControllerConfig, Ssid, WifiController};

esp_bootloader_esp_idf::esp_app_desc!();

/// The network looked for by the directed scan (optional).
const TARGET: Option<&str> = option_env!("PANWEAVE_SCAN_SSID");

fn delay(ms: u64) {
    esp_rtos::CurrentThreadHandle::get().delay(Duration::from_millis(ms));
}

/// Polls `fut` to completion, letting the Wi-Fi tasks run in between.
fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        delay(1);
    }
}

fn scan_type() -> ScanTypeConfig {
    ScanTypeConfig::Active {
        min: Duration::from_millis(40),
        max: Duration::from_millis(80),
    }
}

/// One cycle: a controller, a broadcast scan, a directed scan, dropped.
fn cycle(wifi: esp_hal::peripherals::WIFI<'_>, label: &str) -> usize {
    let mut controller = match WifiController::new(
        wifi,
        ControllerConfig::default().with_initial_config(Config::Station(StationConfig::default())),
    ) {
        Ok(c) => c,
        Err(e) => {
            println!("{label}: Wi-Fi start failed: {e:?}");
            return 0;
        }
    };
    let started = esp_hal::time::Instant::now();
    let all = block_on(
        controller.scan_async(
            &ScanConfig::default()
                .with_show_hidden(true)
                .with_scan_type(scan_type()),
        ),
    );
    let ms = started.elapsed().as_millis();
    let heard = match all {
        Ok(mut aps) => {
            aps.sort_unstable_by_key(|ap| core::cmp::Reverse(ap.signal_strength));
            println!("{label}: {} access points heard in {ms} ms", aps.len());
            for ap in aps.iter().take(10) {
                let name = if ap.ssid.as_str().is_empty() {
                    "(hidden)"
                } else {
                    ap.ssid.as_str()
                };
                println!(
                    "    {name:<24} {:02x?} ch {:>2} {:>4} dBm {:?}",
                    ap.bssid, ap.channel, ap.signal_strength, ap.auth_method
                );
            }
            aps.len()
        }
        Err(e) => {
            println!("{label}: scan failed: {e:?}");
            0
        }
    };
    if let Some(target) = TARGET {
        let Ok(ssid) = Ssid::try_from(target) else {
            println!("    directed: invalid SSID");
            drop(controller);
            return heard;
        };
        let directed = block_on(
            controller.scan_async(
                &ScanConfig::default()
                    .with_ssid(ssid)
                    .with_show_hidden(true)
                    .with_scan_type(ScanTypeConfig::Active {
                        min: Duration::from_millis(40),
                        max: Duration::from_millis(120),
                    }),
            ),
        );
        match directed {
            Ok(aps) if aps.is_empty() => println!("    directed {target:?}: no answer"),
            Ok(aps) => {
                for ap in &aps {
                    println!(
                        "    directed {target:?}: {:02x?} ch {} {} dBm {:?}",
                        ap.bssid, ap.channel, ap.signal_strength, ap.auth_method
                    );
                }
            }
            Err(e) => println!("    directed {target:?}: scan failed: {e:?}"),
        }
    }
    drop(controller);
    heard
}

/// 802.15.4 receives on channel 11 for `ms`, then is dropped.
fn ieee802154_burst(radio: esp_hal::peripherals::IEEE802154<'_>, ms: u64) {
    let mut drv = Ieee802154::new(radio);
    drv.set_config(RadioConfig {
        channel: 11,
        rx_when_idle: true,
        ..RadioConfig::default()
    });
    drv.start_receive();
    delay(ms);
    drop(drv);
}

#[esp_hal::main]
fn main() -> ! {
    let p = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(size: 32 * 1024);
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 64 * 1024);
    let timg0 = TimerGroup::new(p.TIMG0);
    esp_rtos::start(timg0.timer0, p.FROM_CPU_INTR0);
    let mut wifi = p.WIFI;
    let mut radio = p.IEEE802154;

    // Time to attach the console after the reset.
    delay(4000);
    println!("== wifi-scan-check: target {TARGET:?}");
    let mut totals = [0usize; 3];
    for i in 0..3 {
        totals[0] += cycle(wifi.reborrow(), &format_label("A", i));
        delay(1000);
    }
    for i in 0..3 {
        ieee802154_burst(radio.reborrow(), 3000);
        totals[1] += cycle(wifi.reborrow(), &format_label("B", i));
        delay(1000);
    }
    for i in 0..3 {
        totals[2] += cycle(wifi.reborrow(), &format_label("A2", i));
        delay(1000);
    }
    println!(
        "== summary: access points heard per scan, mean of 3: A {}, B {}, A2 {}",
        totals[0] / 3,
        totals[1] / 3,
        totals[2] / 3
    );
    println!("== done");
    loop {
        delay(10_000);
    }
}

/// `"B1"`.
fn format_label(phase: &str, i: usize) -> heapless::String<8> {
    let mut s = heapless::String::new();
    let _ = s.push_str(phase);
    let _ = s.push(char::from(b'1' + u8::try_from(i).unwrap_or(0)));
    s
}
