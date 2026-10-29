//! The sensor's persistent store medium.

use embedded_storage::nor_flash::{
    ErrorType, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash,
};

/// EFR32MG22 flash page (erase unit).
pub const PAGE: usize = 8 * 1024;
/// The store: the last two pages of the 512 KiB part.
pub const STORE_LEN: u32 = 2 * PAGE as u32;
/// Offset of the store in the flash.
#[allow(dead_code)]
pub const STORE_BASE: u32 = 512 * 1024 - STORE_LEN;

/// Flash errors.
#[derive(Debug, Clone, Copy)]
pub struct FlashError(pub NorFlashErrorKind);

impl NorFlashError for FlashError {
    fn kind(&self) -> NorFlashErrorKind {
        self.0
    }
}

/// The EFR32MG22 MSC. Reads use the memory-mapped flash; **page erase
/// and word write are not implemented** (they need the MSC write
/// sequence of the reference manual, §7.3, and testing on a board): both
/// fail, so a firmware built with this driver cannot persist and stops
/// at start-up. It is here so that the link build carries the store's
/// code and RAM.
#[cfg(not(feature = "qemu"))]
pub struct Msc;

#[cfg(not(feature = "qemu"))]
impl ErrorType for Msc {
    type Error = FlashError;
}

#[cfg(not(feature = "qemu"))]
impl ReadNorFlash for Msc {
    const READ_SIZE: usize = 4;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), FlashError> {
        let end = offset as usize + bytes.len();
        if end > STORE_BASE as usize + STORE_LEN as usize {
            return Err(FlashError(NorFlashErrorKind::OutOfBounds));
        }
        for (i, b) in bytes.iter_mut().enumerate() {
            // SAFETY: the flash is memory-mapped from 0 and the range was
            // checked against the part's size.
            *b = unsafe { core::ptr::read_volatile((offset as usize + i) as *const u8) };
        }
        Ok(())
    }

    fn capacity(&self) -> usize {
        512 * 1024
    }
}

#[cfg(not(feature = "qemu"))]
impl NorFlash for Msc {
    const WRITE_SIZE: usize = 4;
    const ERASE_SIZE: usize = PAGE;

    fn erase(&mut self, _from: u32, _to: u32) -> Result<(), FlashError> {
        Err(FlashError(NorFlashErrorKind::Other))
    }

    fn write(&mut self, _offset: u32, _bytes: &[u8]) -> Result<(), FlashError> {
        Err(FlashError(NorFlashErrorKind::Other))
    }
}

/// QEMU: the store over RAM outside the sensor's 32 KiB, with the NOR
/// rules (erase sets a page to 0xFF, a write only clears bits).
#[cfg(feature = "qemu")]
pub struct RamFlash(pub &'static mut [u8; STORE_LEN as usize]);

#[cfg(feature = "qemu")]
impl ErrorType for RamFlash {
    type Error = FlashError;
}

#[cfg(feature = "qemu")]
impl ReadNorFlash for RamFlash {
    const READ_SIZE: usize = 4;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), FlashError> {
        let o = offset as usize;
        let src = self
            .0
            .get(o..o + bytes.len())
            .ok_or(FlashError(NorFlashErrorKind::OutOfBounds))?;
        bytes.copy_from_slice(src);
        Ok(())
    }

    fn capacity(&self) -> usize {
        STORE_LEN as usize
    }
}

#[cfg(feature = "qemu")]
impl NorFlash for RamFlash {
    const WRITE_SIZE: usize = 4;
    const ERASE_SIZE: usize = PAGE;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), FlashError> {
        self.0
            .get_mut(from as usize..to as usize)
            .ok_or(FlashError(NorFlashErrorKind::OutOfBounds))?
            .fill(0xff);
        Ok(())
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), FlashError> {
        let o = offset as usize;
        let dst = self
            .0
            .get_mut(o..o + bytes.len())
            .ok_or(FlashError(NorFlashErrorKind::OutOfBounds))?;
        for (c, b) in dst.iter_mut().zip(bytes) {
            if *c & *b != *b {
                return Err(FlashError(NorFlashErrorKind::Other));
            }
            *c = *b;
        }
        Ok(())
    }
}
