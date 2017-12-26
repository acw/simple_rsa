use digest::{FixedOutput,Input};
use sha1::Sha1;
use sha2::{Sha224,Sha256,Sha384,Sha512};
use std::fmt;

#[derive(Clone)]
pub struct SigningHash {
    pub name: &'static str,
    pub ident: &'static [u8],
    pub run: fn(&[u8]) -> Vec<u8>
}

impl fmt::Debug for SigningHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

pub static SIGNING_HASH_NULL: SigningHash = SigningHash {
    name: "NULL",
    ident: &[],
    run: nohash
};

fn nohash(i: &[u8]) -> Vec<u8> {
    i.to_vec()
}

pub static SIGNING_HASH_SHA1: SigningHash = SigningHash {
    name: "SHA1",
    ident: &[0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,
             0x02,0x1a,0x05,0x00,0x04,0x14],
    run: runsha1
};

fn runsha1(i: &[u8]) -> Vec<u8> {
    let mut d = Sha1::default();
    d.process(i);
    d.fixed_result().as_slice().to_vec()
}

pub static SIGNING_HASH_SHA224: SigningHash = SigningHash {
    name: "SHA224",
    ident: &[0x30,0x2d,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,
             0x01,0x65,0x03,0x04,0x02,0x04,0x05,0x00,0x04,
             0x1c],
    run: runsha224
};

fn runsha224(i: &[u8]) -> Vec<u8> {
    let mut d = Sha224::default();
    d.process(i);
    d.fixed_result().as_slice().to_vec()
}

pub static SIGNING_HASH_SHA256: SigningHash = SigningHash {
    name: "SHA256",
    ident: &[0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,
             0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,
             0x20],
    run: runsha256
};

fn runsha256(i: &[u8]) -> Vec<u8> {
    let mut d = Sha256::default();
    d.process(i);
    d.fixed_result().as_slice().to_vec()
}

pub static SIGNING_HASH_SHA384: SigningHash = SigningHash {
    name: "SHA384",
    ident: &[0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,
             0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,
             0x30],
    run: runsha384
};

fn runsha384(i: &[u8]) -> Vec<u8> {
    let mut d = Sha384::default();
    d.process(i);
    d.fixed_result().as_slice().to_vec()
}

pub static SIGNING_HASH_SHA512: SigningHash = SigningHash {
    name: "SHA512",
    ident: &[0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,
             0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,
             0x40],
    run: runsha512
};

fn runsha512(i: &[u8]) -> Vec<u8> {
    let mut d = Sha512::default();
    d.process(i);
    d.fixed_result().as_slice().to_vec()
}


