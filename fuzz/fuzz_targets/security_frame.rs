//! Auxiliary header parsing and CCM* unprotect never panic on arbitrary
//! input (they must fail cleanly).
#![no_main]
use libfuzzer_sys::fuzz_target;
use panweave_security::aux_header::SecurityLevel;
use panweave_security::cipher::{BlockCipher, SoftwareAes};
use panweave_security::frame::{peek_aux, unprotect_in_place};
use panweave_types::{ExtendedAddress, Key128};

fuzz_target!(|data: &[u8]| {
    let Some((&hl, rest)) = data.split_first() else {
        return;
    };
    let header_len = usize::from(hl % 24);
    let _ = peek_aux(rest, header_len);
    let cipher = SoftwareAes::new(&Key128::from_bytes([0x11; 16]));
    let mut buf = [0u8; 160];
    let n = rest.len().min(buf.len());
    buf[..n].copy_from_slice(&rest[..n]);
    for level in [
        SecurityLevel::EncMic32,
        SecurityLevel::Mic32,
        SecurityLevel::EncMic128,
    ] {
        let mut b = buf;
        let _ = unprotect_in_place(&cipher, level, ExtendedAddress(0x1234), &mut b[..n], header_len);
    }
});
