use x25519_dalek::X25519_BASEPOINT_BYTES;

use crate::Error;

pub(crate) fn pub_key(k: [u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(k, X25519_BASEPOINT_BYTES)
}

pub(crate) fn x25519(k: [u8; 32], u: [u8; 32]) -> Result<[u8; 32], Error> {
    let out = x25519_dalek::x25519(k, u);
    if out.iter().any(|b| *b != 0u8) {
        Ok(out)
    } else {
        Err(Error::Dh)
    }
}
