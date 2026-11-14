//! Random values from the operating system.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn bytes<const N: usize>() -> [u8; N] {
    let mut buffer = [0u8; N];
    // Without randomness no token can be made safely, and there is nothing to fall back on.
    getrandom::fill(&mut buffer).expect("the operating system's random generator failed");
    buffer
}

/// 32 random bytes, URL-safe base64 without padding: a refresh token.
pub(crate) fn token() -> String {
    URL_SAFE_NO_PAD.encode(bytes::<32>())
}

/// 16 random bytes in hex: a family or token identifier.
pub(crate) fn id() -> String {
    hex(&bytes::<16>())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            // Writing to a String cannot fail.
            let _ = write!(out, "{byte:02x}");
            out
        })
}
