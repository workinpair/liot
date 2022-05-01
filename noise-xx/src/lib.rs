#![no_std]

mod cipher_state;
mod handshake;
mod symmetric_state;
mod transport;
mod x25519;

use cipher_state::CipherState;
pub use handshake::Handshake;
use symmetric_state::SymmetricState;
pub use transport::{NoiseRead, NoiseWrite, Transport};

#[derive(Debug)]
pub enum Error {
    Input,
    Decrypt,
    Dh,
    NotMyTurn,
    NeedUpgrade,
}

#[cfg(test)]
mod test {
    use crate::*;
    extern crate alloc;

    const PROT_NAME: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

    #[test]
    fn test_init_using_snow() {
        let msg = b"msg";

        let e = [0u8; 32];
        let s = [1u8; 32];
        let re = [2u8; 32];
        let rs = [3u8; 32];

        let mut buf_init = [0u8; 100];
        let buf_init = &mut buf_init;
        let mut buf_resp = [0u8; 100];
        let buf_resp = &mut buf_resp;

        let mut resp = snow::Builder::new(PROT_NAME.parse().unwrap())
            .local_private_key(&rs)
            .fixed_ephemeral_key_for_testing_only(&re)
            .build_responder()
            .unwrap();

        let mut init = Handshake::init(e, s, &[]);

        let len = init.write_message(msg, buf_init).unwrap();
        let len = resp.read_message(&buf_init[..len], buf_resp).unwrap();

        assert_eq!(&buf_resp[..len], msg);

        let len = resp.write_message(msg, buf_resp).unwrap();
        let len = init.read_message(&buf_resp[..len], buf_init).unwrap();
        assert_eq!(&buf_init[..len], msg);

        let len = init.write_message(msg, buf_init).unwrap();
        let len = resp.read_message(&buf_init[..len], buf_resp).unwrap();
        assert_eq!(&buf_resp[..len], msg);

        let mut resp = resp.into_transport_mode().unwrap();
        let mut init = init.upgrade().unwrap();

        let len = init.write_message("hello".as_bytes(), buf_init).unwrap();
        let len = resp.read_message(&buf_init[..len], buf_resp).unwrap();
        assert_eq!(&buf_resp[..len], b"hello");
    }

    #[test]
    fn test_resp_using_snow() {
        let msg = b"msg";

        let e = [0u8; 32];
        let s = [1u8; 32];
        let re = [2u8; 32];
        let rs = [3u8; 32];

        let mut buf_init = [0u8; 100];
        let buf_init = &mut buf_init;
        let mut buf_resp = [0u8; 100];
        let buf_resp = &mut buf_resp;

        let mut init = snow::Builder::new(PROT_NAME.parse().unwrap())
            .local_private_key(&rs)
            .fixed_ephemeral_key_for_testing_only(&re)
            .build_initiator()
            .unwrap();

        let mut resp = Handshake::resp(e, s, &[]);

        let len = init.write_message(msg, buf_init).unwrap();
        let len = resp.read_message(&buf_init[..len], buf_resp).unwrap();

        assert_eq!(&buf_resp[..len], msg);

        let len = resp.write_message(msg, buf_resp).unwrap();
        let len = init.read_message(&buf_resp[..len], buf_init).unwrap();
        assert_eq!(&buf_init[..len], msg);

        let len = init.write_message(msg, buf_init).unwrap();
        let len = resp.read_message(&buf_init[..len], buf_resp).unwrap();
        assert_eq!(&buf_resp[..len], msg);

        let mut init = init.into_transport_mode().unwrap();
        let mut resp = resp.upgrade().unwrap();

        let len = init.write_message("hello".as_bytes(), buf_init).unwrap();
        let len = resp.read_message(&buf_init[..len], buf_resp).unwrap();
        assert_eq!(&buf_resp[..len], b"hello");
    }
}
