use crate::{
    cipher_state::TAG_LEN,
    x25519::{pub_key, x25519},
    Error, SymmetricState, Transport,
};

pub(crate) const DH_LEN: usize = 32;
type DHKey = [u8; 32];

mod handshake_state {
    pub enum HandshakeState {
        I1,
        I2,
        I3,
        R1,
        R2,
        R3,
        IDone,
        RDone,
    }
    impl HandshakeState {
        pub fn overhead(&self) -> usize {
            match self {
                Self::I1 | Self::R1 => 32,
                Self::I2 | Self::R2 => 96,
                Self::I3 | Self::R3 => 64,
                Self::IDone | Self::RDone => todo!(),
            }
        }
        pub fn next(&mut self) {
            match self {
                Self::I1 => *self = Self::I2,
                Self::I2 => *self = Self::I3,
                Self::I3 => *self = Self::IDone,
                Self::R1 => *self = Self::R2,
                Self::R2 => *self = Self::R3,
                Self::R3 => *self = Self::RDone,
                Self::IDone => todo!(),
                Self::RDone => todo!(),
            }
        }
    }
}
use handshake_state::HandshakeState::{self, *};

//
//  -> e
//  <- e, ee, s, es
//  -> s, se
pub struct Handshake {
    e: [u8; DH_LEN],
    s: [u8; DH_LEN],
    re: [u8; DH_LEN],
    rs: [u8; DH_LEN],
    state: HandshakeState,
    sym: SymmetricState,
}

impl Handshake {
    pub fn new(init: bool, e: DHKey, s: DHKey, prologue: &[u8]) -> Self {
        let mut sym = SymmetricState::new();
        sym.mix_hash(prologue);
        Self {
            e,
            s,
            re: [0; 32],
            rs: [0; 32],
            state: if init { I1 } else { R1 },
            sym,
        }
    }
    pub fn init(e: DHKey, s: DHKey, prologue: &[u8]) -> Self {
        Self::new(true, e, s, prologue)
    }
    pub fn resp(e: DHKey, s: DHKey, prologue: &[u8]) -> Self {
        Self::new(false, e, s, prologue)
    }
    pub fn upgrade(self) -> Result<Transport, Error> {
        let (send, recv) = match self.state {
            IDone => self.sym.split(),
            RDone => {
                let (c1, c2) = self.sym.split();
                (c2, c1)
            }
            _ => return Err(Error::NotMyTurn),
        };
        Ok(Transport {
            rs: self.rs,
            send,
            recv,
        })
    }
    pub fn read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, Error> {
        if message.len() < self.state.overhead() {
            return Err(Error::Input);
        }
        if payload.len() < message.len() - self.state.overhead() {
            return Err(Error::Input);
        }

        let prev_sym = self.sym.clone();
        let result = self._read_message(message, payload);
        if result.is_ok() {
            self.state.next();
        } else {
            self.sym = prev_sym;
        }
        result
    }
    pub fn write_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, Error> {
        if message.len() < self.state.overhead() + payload.len() {
            return Err(Error::Input);
        }
        let prev_sym = self.sym.clone();

        let result = self._write_message(payload, message);

        if result.is_ok() {
            self.state.next();
        } else {
            self.sym = prev_sym;
        }
        result
    }
    fn _read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, Error> {
        match self.state {
            I1 | R2 | I3 => Err(Error::NotMyTurn),
            IDone | RDone => Err(Error::NeedUpgrade),
            R1 => {
                let (msg_re, msg_rp) = message.split_at(DH_LEN);
                let (payload, _) = payload.split_at_mut(msg_rp.len());
                // e
                self.sym.decrypt_and_hash(msg_re, &mut self.re)?;

                // payload
                self.sym.decrypt_and_hash(msg_rp, payload)?;
                Ok(payload.len())
            }
            I2 => {
                let (msg_e, rest) = message.split_at(DH_LEN);
                let (msg_s, msg_p) = rest.split_at(DH_LEN + TAG_LEN);

                let (payload, _) = payload.split_at_mut(msg_p.len() - TAG_LEN);

                // e
                self.sym.decrypt_and_hash(msg_e, &mut self.re)?;

                // ee
                self.sym.mix_key(&x25519(self.e, self.re)?);

                // s
                self.sym.decrypt_and_hash(msg_s, &mut self.rs)?;

                // es
                self.sym.mix_key(&x25519(self.e, self.rs)?);

                // payload
                self.sym.decrypt_and_hash(msg_p, payload)?;
                Ok(payload.len())
            }
            R3 => {
                let (msg_s, msg_p) = message.split_at(DH_LEN + TAG_LEN);

                let (payload, _) = payload.split_at_mut(msg_p.len() - TAG_LEN);

                // s
                self.sym.decrypt_and_hash(msg_s, &mut self.rs)?;

                // se
                self.sym.mix_key(&x25519(self.e, self.rs)?);

                // payload
                self.sym.decrypt_and_hash(msg_p, payload)?;
                Ok(payload.len())
            }
        }
    }
    fn _write_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, Error> {
        match self.state {
            R1 | I2 | R3 => Err(Error::NotMyTurn),
            IDone | RDone => Err(Error::NeedUpgrade),
            I1 => {
                let (msg_e, rest) = message.split_at_mut(DH_LEN);
                let (msg_p, _) = &mut rest.split_at_mut(payload.len());

                // e
                self.sym.encrypt_and_hash(&pub_key(self.e), msg_e)?;

                // payload
                self.sym.encrypt_and_hash(payload, msg_p)?;

                Ok(msg_e.len() + msg_p.len())
            }
            R2 => {
                let (msg_e, rest) = message.split_at_mut(DH_LEN);
                let (msg_s, rest) = rest.split_at_mut(DH_LEN + TAG_LEN);
                let (msg_p, _) = rest.split_at_mut(payload.len() + TAG_LEN);

                // e
                self.sym.encrypt_and_hash(&pub_key(self.e), msg_e)?;

                // ee
                self.sym.mix_key(&x25519(self.e, self.re)?);

                // s
                self.sym.encrypt_and_hash(&pub_key(self.s), msg_s)?;

                // es
                self.sym.mix_key(&x25519(self.s, self.re)?);

                // payload
                self.sym.encrypt_and_hash(payload, msg_p)?;
                Ok(msg_e.len() + msg_s.len() + msg_p.len())
            }
            I3 => {
                let (msg_s, rest) = message.split_at_mut(DH_LEN + TAG_LEN);
                let (msg_p, _) = rest.split_at_mut(payload.len() + TAG_LEN);

                // s
                self.sym.encrypt_and_hash(&pub_key(self.s), msg_s)?;

                // se
                self.sym.mix_key(&x25519(self.s, self.re)?);

                // payload
                self.sym.encrypt_and_hash(payload, msg_p)?;
                Ok(msg_s.len() + msg_p.len())
            }
        }
    }
}
