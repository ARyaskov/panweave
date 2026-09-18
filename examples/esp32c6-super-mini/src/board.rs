//! The ESP32-C6 Super Mini brought up for the stack.
//!
//! Pins (the common "Super Mini" layout: 5V / GND / 3V3 on one edge,
//! GPIO 0–23 around the board, USB-C at the top):
//!
//! * [`LED`] — the blue LED next to the USB connector, GPIO 15 (active
//!   high; boards with a WS2812 instead have it on GPIO 8 and need a
//!   driver of their own);
//! * [`BUTTON`] — the BOOT button, GPIO 9 (active low, pulled up).
//!
//! Persistent data lives in the `nvs` partition of espflash's default
//! partition table (24 KiB at 0x9000), which nothing else on a bare-metal
//! image uses: the region is a [`NorFlashStore`] of two 12 KiB halves.
//! A different partition table only has to keep that region, or pass
//! its own offsets to [`Board::init_with_store`].

use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull};
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::tsens::{self, TemperatureSensor};
use esp_storage::FlashStorage;
use panweave::types::ExtendedAddress;
use panweave::types::rng::{CryptoRng, Rng as PanweaveRng};
use panweave_storage::nor_flash::NorFlashStore;

use crate::radio::Radio;

/// The LED pin.
pub const LED: u8 = 15;
/// The BOOT button pin.
pub const BUTTON: u8 = 9;
/// Flash offset of the stack's storage region (the `nvs` partition).
pub const STORE_OFFSET: u32 = 0x9000;
/// Length of the storage region.
pub const STORE_LEN: u32 = 0x6000;

/// The stack's storage: the on-chip flash.
pub type FlashStore = NorFlashStore<FlashStorage<'static>>;

/// The chip's true random number generator, entropy from the SAR ADC
/// noise source and the radio, as the stack's [`CryptoRng`].
pub struct Rng {
    _source: TrngSource<'static>,
    trng: Trng,
}

impl PanweaveRng for Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.trng.read(dest);
    }

    fn next_u32(&mut self) -> u32 {
        self.trng.random()
    }
}

impl CryptoRng for Rng {}

/// The board's peripherals, ready for a `Node`.
pub struct Board {
    /// The 802.15.4 radio.
    pub radio: Radio,
    /// Persistent storage for the stack.
    pub storage: FlashStore,
    /// The TRNG.
    pub rng: Rng,
    /// This device's IEEE address.
    pub ieee: ExtendedAddress,
    /// The blue LED.
    pub led: Output<'static>,
    /// The BOOT button (low while pressed).
    pub button: Input<'static>,
    /// The on-chip temperature sensor.
    pub tsens: TemperatureSensor<'static>,
}

impl Board {
    /// Initializes the chip at its maximum clock, the heap `esp-radio`
    /// needs, the radio, the flash store in the default region, the
    /// TRNG, the LED and the button.
    pub fn init() -> Self {
        Self::init_with_store(STORE_OFFSET, STORE_LEN)
    }

    /// [`Board::init`] with the storage region at `store_offset`,
    /// `store_len` octets (both multiples of 8 KiB).
    pub fn init_with_store(store_offset: u32, store_len: u32) -> Self {
        let p = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
        esp_alloc::heap_allocator!(size: 32 * 1024);
        let ieee = ieee_address();
        let radio = Radio::new(p.IEEE802154, ieee);
        let flash = FlashStorage::new(p.FLASH);
        let storage = NorFlashStore::new(flash, store_offset, store_len)
            .unwrap_or_else(|_| panic!("storage region {store_offset:#x}+{store_len:#x}"));
        let source = TrngSource::new(p.RNG, p.ADC1);
        let trng = Trng::try_new().unwrap_or_else(|_| panic!("TRNG source"));
        let led = Output::new(p.GPIO15, Level::Low, OutputConfig::default());
        let button = Input::new(p.GPIO9, InputConfig::default().with_pull(Pull::Up));
        let tsens = TemperatureSensor::new(p.TSENS, tsens::Config::default())
            .unwrap_or_else(|_| panic!("temperature sensor"));
        Board {
            radio,
            storage,
            rng: Rng {
                _source: source,
                trng,
            },
            ieee,
            led,
            button,
            tsens,
        }
    }
}

/// The die temperature in °C.
pub fn temperature_celsius(tsens: &TemperatureSensor<'_>) -> f32 {
    tsens.get_temperature().to_celsius()
}

/// This chip's IEEE address: the factory base MAC (EUI-48) widened to an
/// EUI-64 the standard way, `FF FE` in the middle.
pub fn ieee_address() -> ExtendedAddress {
    let mac = esp_hal::efuse::base_mac_address();
    let m = mac.as_bytes();
    let eui = [m[0], m[1], m[2], 0xFF, 0xFE, m[3], m[4], m[5]];
    ExtendedAddress(u64::from_be_bytes(eui))
}
