//! `ota`: offers an OTA image file to devices and serves its bytes while
//! the hub asks for them, until the device finished (or Ctrl+C).
//!
//! The image is read from a local file and its header checked (file
//! identifier, header version and length, the total size matching the
//! file) before it is offered. Signatures in the file are the device's to
//! verify; the hub never parses the image.

use std::sync::atomic::Ordering;
use std::sync::mpsc::RecvTimeoutError;
use std::time::Duration;

use panweave_hub::model::Ieee;
use panweave_hub::protocol::{
    Event, MAX_OTA_CHUNK, Message, OtaImage, OtaOffer, OtaStatus, Request, Response,
};

use crate::{Hub, STOP, error_text, expect_done, flag_value, ieee};

/// OTA file identifier (ZCL8 §11.4.2.1).
const FILE_IDENTIFIER: u32 = 0x0BEE_F11E;

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// The identity of an OTA file, from its header (§11.4.2).
pub(crate) fn image_of(file: &[u8]) -> Result<OtaImage, String> {
    let bad = |what: &str| format!("not an OTA image: {what}");
    if u32_at(file, 0) != Some(FILE_IDENTIFIER) {
        return Err(bad("file identifier is not 0x0BEEF11E"));
    }
    if u16_at(file, 4) != Some(0x0100) {
        return Err(bad("header version is not 0x0100"));
    }
    let header_len = u16_at(file, 6).ok_or_else(|| bad("truncated header"))?;
    if header_len < 56 || usize::from(header_len) > file.len() {
        return Err(bad("header length"));
    }
    let size = u32_at(file, 52).ok_or_else(|| bad("truncated header"))?;
    if usize::try_from(size).ok() != Some(file.len()) {
        return Err(format!(
            "the header's total image size ({size}) is not the file size ({})",
            file.len()
        ));
    }
    Ok(OtaImage {
        manufacturer_code: u16_at(file, 10).ok_or_else(|| bad("truncated header"))?,
        image_type: u16_at(file, 12).ok_or_else(|| bad("truncated header"))?,
        file_version: u32_at(file, 14).ok_or_else(|| bad("truncated header"))?,
        size,
    })
}

fn describe_status(s: &OtaStatus) -> String {
    match s.offer {
        None => "no image offered".into(),
        Some(o) => format!(
            "offered: manufacturer {:#06x}, image type {:#06x}, version {:#010x}, {} octets{}{}; {}",
            o.image.manufacturer_code,
            o.image.image_type,
            o.image.file_version,
            o.image.size,
            o.target
                .map_or_else(String::new, |t| format!(", only to {}", Ieee(t))),
            if o.allow_downgrade {
                ", downgrades allowed"
            } else {
                ""
            },
            match s.device {
                Some(d) => format!("{} at offset {}", Ieee(d), s.offset),
                None => "no device downloading".into(),
            }
        ),
    }
}

/// Sends the octets the hub wants.
fn send_data(hub: &mut Hub, file: &[u8], offset: u32, length: u16) -> Result<(), String> {
    let start = usize::try_from(offset).map_err(|e| e.to_string())?;
    let end = (start + usize::from(length)).min(file.len());
    let mut at = start;
    while at < end {
        let n = (end - at).min(MAX_OTA_CHUNK);
        let data = heapless::Vec::from_slice(file.get(at..at + n).unwrap_or_default())
            .map_err(|_| "chunk too large".to_string())?;
        let at32 = u32::try_from(at).map_err(|e| e.to_string())?;
        expect_done(hub.call(Request::OtaData { offset: at32, data })?)?;
        at += n;
    }
    Ok(())
}

pub(crate) fn run(hub: &mut Hub, args: &[&str], all: &[String]) -> Result<(), String> {
    match args {
        ["status"] => match hub.call(Request::GetOtaStatus)? {
            Response::OtaStatus(s) => {
                println!("{}", describe_status(&s));
                Ok(())
            }
            Response::Error(e) => Err(error_text(e)),
            r => Err(format!("unexpected response {r:?}")),
        },
        ["cancel"] => {
            expect_done(hub.call(Request::OtaCancel)?)?;
            println!("offer withdrawn");
            Ok(())
        }
        ["update", path, ..] => {
            let file = std::fs::read(path).map_err(|e| format!("reading {path}: {e}"))?;
            let image = image_of(&file)?;
            let target = match all.iter().position(|a| a == "--ieee") {
                Some(i) => Some(ieee(all.get(i + 1).ok_or("--ieee needs an address")?)?),
                None => None,
            };
            let offer = OtaOffer {
                image,
                target,
                allow_downgrade: all.iter().any(|a| a == "--allow-downgrade"),
            };
            let wait = Duration::from_secs(flag_value(all, "--wait", 3600u64)?);
            expect_done(hub.call(Request::OtaOffer(offer))?)?;
            println!(
                "offered version {:#010x} ({} octets); waiting for a device to ask (it may take \
                 until its next query; Ctrl+C withdraws the offer)",
                image.file_version, image.size
            );
            serve(hub, &file, wait)
        }
        _ => Err(crate::USAGE.into()),
    }
}

/// Answers the hub's data requests until a device finishes.
fn serve(hub: &mut Hub, file: &[u8], wait: Duration) -> Result<(), String> {
    let deadline = std::time::Instant::now() + wait;
    while !STOP.load(Ordering::SeqCst) {
        if std::time::Instant::now() >= deadline {
            let _ = hub.call(Request::OtaCancel);
            return Err("no device finished in time; offer withdrawn".into());
        }
        match hub.rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Message::Event { event, .. }) => match event {
                Event::OtaDataWanted { offset, length } => send_data(hub, file, offset, length)?,
                Event::OtaProgress { ieee, offset, size } => {
                    println!(
                        "{}: {offset}/{size} octets ({} %)",
                        Ieee(ieee),
                        u64::from(offset) * 100 / u64::from(size.max(1))
                    );
                }
                Event::OtaFinished { ieee, status: 0 } => {
                    println!("{}: image verified, upgrading now", Ieee(ieee));
                    return Ok(());
                }
                Event::OtaFinished { ieee, status } => {
                    return Err(format!(
                        "{}: download ended with status {status:#04x}",
                        Ieee(ieee)
                    ));
                }
                _ => {}
            },
            Ok(_) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Err("serial port closed".into()),
        }
    }
    let _ = hub.call(Request::OtaCancel);
    Err("interrupted; offer withdrawn".into())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    fn file(size: u32) -> Vec<u8> {
        let mut f = vec![0u8; size as usize];
        f[0..4].copy_from_slice(&FILE_IDENTIFIER.to_le_bytes());
        f[4..6].copy_from_slice(&0x0100u16.to_le_bytes());
        f[6..8].copy_from_slice(&56u16.to_le_bytes());
        f[10..12].copy_from_slice(&0x1234u16.to_le_bytes());
        f[12..14].copy_from_slice(&7u16.to_le_bytes());
        f[14..18].copy_from_slice(&0x0200_0001u32.to_le_bytes());
        f[52..56].copy_from_slice(&size.to_le_bytes());
        f
    }

    #[test]
    fn headers_are_read_and_checked() {
        let img = image_of(&file(300)).unwrap();
        assert_eq!(
            img,
            OtaImage {
                manufacturer_code: 0x1234,
                image_type: 7,
                file_version: 0x0200_0001,
                size: 300
            }
        );
        let mut f = file(300);
        f.push(0);
        assert!(image_of(&f).unwrap_err().contains("total image size"));
        let mut f = file(300);
        f[0] = 0;
        assert!(image_of(&f).is_err());
        assert!(image_of(&[0u8; 10]).is_err());
    }
}
