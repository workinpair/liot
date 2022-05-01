use core::convert::TryInto;

use crate::cipher_state::CipherState;
use blake2::Digest;
use hkdf::Hkdf;

//const PROT_NAME: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const PRE_H_NAME: [u8; 32] = [
    28, 238, 221, 129, 197, 244, 88, 178, 37, 146, 61, 194, 80, 119, 135, 191, 21, 111, 146, 81,
    252, 23, 196, 90, 246, 50, 99, 169, 41, 252, 30, 210,
];
#[derive(Clone)]
pub(crate) struct SymmetricState {
    ck: [u8; 32],
    h: [u8; 32],
    cipher: CipherState,
    has_key: bool,
}

impl SymmetricState {
    pub(crate) fn new() -> Self {
        Self {
            ck: PRE_H_NAME,
            h: PRE_H_NAME,
            cipher: CipherState::new([0u8; 32]),
            has_key: false,
        }
    }
    pub(crate) fn mix_key(&mut self, input_material: &[u8]) {
        let hkdf = Hkdf::<blake2::Blake2s>::new(Some(&self.ck), input_material);
        let mut output = [0u8; 64];
        hkdf.expand(&[], &mut output).unwrap();
        self.ck.copy_from_slice(&output[..32]);
        self.cipher = CipherState::new(output[32..].try_into().unwrap());
        self.has_key = true;
    }
    pub(crate) fn mix_hash(&mut self, data: &[u8]) {
        let mut hash = blake2::Blake2s::new();
        hash.update(&self.h);
        hash.update(data);
        self.h = hash.finalize().into();
    }
    pub(crate) fn encrypt_and_hash(
        &mut self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, crate::Error> {
        let len = if self.has_key {
            self.cipher.encrypt_with_ad(&self.h, payload, message)?
        } else {
            if message.len() < payload.len() {
                return Err(crate::Error::Input);
            }
            let (message, _) = message.split_at_mut(payload.len());
            message.copy_from_slice(payload);
            payload.len()
        };
        self.mix_hash(&message[..len]);
        Ok(len)
    }
    pub(crate) fn decrypt_and_hash(
        &mut self,
        message: &[u8],
        payload: &mut [u8],
    ) -> Result<usize, crate::Error> {
        let len = if self.has_key {
            self.cipher.decrypt_with_ad(&self.h, message, payload)?
        } else {
            let (payload, _) = payload.split_at_mut(message.len());
            payload.copy_from_slice(message);
            message.len()
        };
        self.mix_hash(message);
        Ok(len)
    }

    pub(crate) fn split(self) -> (CipherState, CipherState) {
        let hkdf = Hkdf::<blake2::Blake2s>::new(Some(&self.ck), &[]);
        let mut output = [0u8; 64];
        hkdf.expand(&[], &mut output).unwrap();
        (
            CipherState::new(output[..32].try_into().unwrap()),
            CipherState::new(output[32..].try_into().unwrap()),
        )
    }
}
