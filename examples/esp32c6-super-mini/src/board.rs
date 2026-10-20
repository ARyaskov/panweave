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
//!
//! The hub firmware keeps its device registry apart from the stack's
//! records, in a data partition labelled [`HUB_PARTITION`] that its own
//! partition table (`partitions-hub.csv`) adds; [`Board::init_hub`]
//! finds it in the partition table on flash and opens a second store
//! there, both stores sharing the one flash driver.

extern crate alloc;

use core::cell::RefCell;

use embedded_storage::nor_flash::{ErrorType, NorFlash, ReadNorFlash};
use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull};
use esp_hal::peripherals::{RTC_TIMER, USB_DEVICE};
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
/// Label of the hub's registry partition.
pub const HUB_PARTITION: &str = "hubdata";

/// The stack's storage: the on-chip flash.
pub type FlashStore = NorFlashStore<FlashStorage<'static>>;

/// A store on the flash shared with another store.
pub type SharedStore = NorFlashStore<SharedFlash>;

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

/// The on-chip flash, shared by several stores. The firmware is a single
/// loop and flash is never touched from an interrupt, so a `RefCell` is
/// enough: every operation borrows the driver for its own duration.
#[derive(Clone, Copy)]
pub struct SharedFlash(&'static RefCell<FlashStorage<'static>>);

impl ErrorType for SharedFlash {
    type Error = <FlashStorage<'static> as ErrorType>::Error;
}

impl ReadNorFlash for SharedFlash {
    const READ_SIZE: usize = <FlashStorage<'static> as ReadNorFlash>::READ_SIZE;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0.borrow_mut().read(offset, bytes)
    }

    fn capacity(&self) -> usize {
        self.0.borrow().capacity()
    }
}

impl NorFlash for SharedFlash {
    const WRITE_SIZE: usize = <FlashStorage<'static> as NorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <FlashStorage<'static> as NorFlash>::ERASE_SIZE;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        self.0.borrow_mut().erase(from, to)
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.borrow_mut().write(offset, bytes)
    }
}

/// The board's peripherals, ready for a `Node`.
pub struct Board<S = FlashStore> {
    /// The 802.15.4 radio.
    pub radio: Radio,
    /// Persistent storage for the stack.
    pub storage: S,
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
    /// The USB Serial/JTAG controller behind the USB-C connector.
    pub usb: USB_DEVICE<'static>,
    /// The RTC timer peripheral (its watchdog resets a hung firmware).
    pub rtc_timer: RTC_TIMER<'static>,
}

/// Everything but the stack's storage.
struct Parts {
    radio: Radio,
    rng: Rng,
    ieee: ExtendedAddress,
    led: Output<'static>,
    button: Input<'static>,
    tsens: TemperatureSensor<'static>,
    usb: USB_DEVICE<'static>,
    rtc_timer: RTC_TIMER<'static>,
}

impl Parts {
    /// Initializes the chip at its maximum clock, the heap `esp-radio`
    /// needs, the radio, the TRNG, the LED and the button; returns the
    /// flash driver alongside.
    fn init() -> (Self, FlashStorage<'static>) {
        let p = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
        esp_alloc::heap_allocator!(size: 32 * 1024);
        let ieee = ieee_address();
        let radio = Radio::new(p.IEEE802154, ieee);
        let flash = FlashStorage::new(p.FLASH);
        let source = TrngSource::new(p.RNG, p.ADC1);
        let trng = Trng::try_new().unwrap_or_else(|_| panic!("TRNG source"));
        let led = Output::new(p.GPIO15, Level::Low, OutputConfig::default());
        let button = Input::new(p.GPIO9, InputConfig::default().with_pull(Pull::Up));
        let tsens = TemperatureSensor::new(p.TSENS, tsens::Config::default())
            .unwrap_or_else(|_| panic!("temperature sensor"));
        let parts = Parts {
            radio,
            rng: Rng {
                _source: source,
                trng,
            },
            ieee,
            led,
            button,
            tsens,
            usb: p.USB_DEVICE,
            rtc_timer: p.RTC_TIMER,
        };
        (parts, flash)
    }

    fn with_storage<S>(self, storage: S) -> Board<S> {
        Board {
            radio: self.radio,
            storage,
            rng: self.rng,
            ieee: self.ieee,
            led: self.led,
            button: self.button,
            tsens: self.tsens,
            usb: self.usb,
            rtc_timer: self.rtc_timer,
        }
    }
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
        let (parts, flash) = Parts::init();
        let storage = NorFlashStore::new(flash, store_offset, store_len)
            .unwrap_or_else(|_| panic!("storage region {store_offset:#x}+{store_len:#x}"));
        parts.with_storage(storage)
    }
}

impl Board<SharedStore> {
    /// The hub's board: the stack's store in the default region, as for
    /// every other image, and the registry store in the [`HUB_PARTITION`]
    /// partition — `None` when the flashed partition table has no such
    /// partition (or a malformed one), in which case nothing is written
    /// outside the stack's region.
    pub fn init_hub() -> (Self, Option<SharedStore>) {
        let (parts, mut flash) = Parts::init();
        let hub_region = find_partition(&mut flash, HUB_PARTITION);
        let flash: &'static RefCell<FlashStorage<'static>> =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(RefCell::new(flash)));
        let storage = NorFlashStore::new(SharedFlash(flash), STORE_OFFSET, STORE_LEN)
            .unwrap_or_else(|_| panic!("storage region {STORE_OFFSET:#x}+{STORE_LEN:#x}"));
        let hub = hub_region
            .and_then(|(offset, len)| NorFlashStore::new(SharedFlash(flash), offset, len).ok());
        (parts.with_storage(storage), hub)
    }
}

/// The region of the data partition labelled `label`, trimmed to whole
/// pairs of sectors, provided it does not overlap the stack's region.
fn find_partition(flash: &mut FlashStorage<'static>, label: &str) -> Option<(u32, u32)> {
    use esp_bootloader_esp_idf::partitions::{self, PARTITION_TABLE_MAX_LEN};
    let mut buf = [0u8; PARTITION_TABLE_MAX_LEN];
    let table = partitions::read_partition_table(flash, &mut buf).ok()?;
    let entry = table.iter().find(|p| p.label_as_str() == label)?;
    let sector = FlashStorage::SECTOR_SIZE;
    let offset = entry.offset();
    let len = entry.len() / (2 * sector) * (2 * sector);
    let overlaps = offset < STORE_OFFSET + STORE_LEN && STORE_OFFSET < offset + len;
    (offset % sector == 0 && len >= 2 * sector && !overlaps).then_some((offset, len))
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
