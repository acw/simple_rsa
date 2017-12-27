//! A simple RSA library.
//!
//! This library performs all the standard bits and pieces that you'd expect
//! from an RSA library, and does so using only Rust. It's a bit slow at the
//! moment, but it gets the job done.
//!
//! Key generation is supported, using either the native `OsRng` or a random
//! number generator of your choice. Obviously, you should be careful to use
//! a cryptographically-sound random number generator sufficient for the
//! security level you're going for.
//!
//! Signing and verification are via standard PKCS1 padding, but can be
//! adjusted based on the exact hash you want. This library also supports
//! somewhat arbitrary signing mechanisms used by your weirder network
//! protocols. (I'm looking at you, Tor.)
//!
//! Encryption and decryption are via the OAEP mechanism, as described in
//! NIST documents.
//!
extern crate digest;
#[macro_use]
extern crate lazy_static;
extern crate num;
#[cfg(test)]
#[macro_use]
extern crate quickcheck;
extern crate rand;
extern crate sha1;
extern crate sha2;

mod numutils;
mod signing_hashes;

use digest::{FixedOutput,Input};
use num::{BigUint,FromPrimitive,One,Zero};
use numutils::{i2osp,o2isp,modinv,generate_pq};
use rand::{OsRng,Rng};
use std::io;

pub use signing_hashes::{SigningHash,
                         SIGNING_HASH_NULL,
                         SIGNING_HASH_SHA1,
                         SIGNING_HASH_SHA224,
                         SIGNING_HASH_SHA256,
                         SIGNING_HASH_SHA384,
                         SIGNING_HASH_SHA512};


/// An RSA public and private key.
#[derive(Clone,Debug)]
pub struct RSAKeyPair {
    pub private: RSAPrivateKey,
    pub public:  RSAPublicKey
}

#[derive(Debug)]
pub enum RSAKeyGenError {
    InvalidKeySize(usize), RngFailure(io::Error)
}

impl From<io::Error> for RSAKeyGenError {
    fn from(e: io::Error) -> RSAKeyGenError {
        RSAKeyGenError::RngFailure(e)
    }
}

impl RSAKeyPair {
    /// Generates a fresh RSA key pair of the given bit size. Valid bit sizes
    /// are 512, 1024, 2048, 3072, 4096, 7680, 8192, and 15360. If you
    /// actually want to protect data, use a value greater than or equal to
    /// 2048. If you don't want to spend all day waiting for RSA computations
    /// to finish, choose a value less than or equal to 4096.
    ///
    /// This routine will use `OsRng` for entropy. If you want to use your
    /// own random number generator, use `generate_w_rng`.
    pub fn generate(len_bits: usize) -> Result<RSAKeyPair,RSAKeyGenError> {
        let mut rng = OsRng::new()?;
        RSAKeyPair::generate_w_rng(&mut rng, len_bits)
    }

    /// Generates a fresh RSA key pair of the given bit size. Valid bit sizes
    /// are 512, 1024, 2048, 3072, 4096, 7680, 8192, and 15360. If you
    /// actually want to protect data, use a value greater than or equal to
    /// 2048. If you don't want to spend all day waiting for RSA computations
    /// to finish, choose a value less than or equal to 4096.
    ///
    /// If you provide your own random number generator that is not `OsRng`,
    /// you should know what you're doing, and be using a cryptographically-
    /// strong RNG of your own choosing. We've warned you. Use a good one.
    /// So now it's on you.
    pub fn generate_w_rng<G: Rng>(rng: &mut G, len_bits: usize)
        -> Result<RSAKeyPair,RSAKeyGenError>
    {
        let len_bytes = len_bits / 8;
        let e32: u32 = 65537;
        let e = BigUint::from(e32);
        match generate_pq(rng, &e, len_bits) {
            None =>
                return Err(RSAKeyGenError::InvalidKeySize(len_bits)),
            Some((p, q)) => {
                let n = &p * &q;
                let one: BigUint = One::one();
                let phi = (p - &one) * (q - &one);
                let e = BigUint::from_u32(65537).unwrap();
                let d = modinv(&e, &phi);
                let public_key  = RSAPublicKey{ key_length: len_bytes, n: n.clone(), e: e};
                let private_key = RSAPrivateKey{key_length: len_bytes, n: n,         d: d};
                return Ok(RSAKeyPair{ private: private_key, public: public_key })
            }
        }
    }
}


/// A RSA public key.
#[derive(Clone,Debug)]
pub struct RSAPublicKey {
    key_length: usize,
    n: BigUint,
    e: BigUint
}

#[derive(Debug)]
pub enum RSAError {
    BadMessageSize,
    KeyTooSmallForHash,
    DecryptionError,
    DecryptHashMismatch,
    RandomGenError(io::Error)
}

impl From<io::Error> for RSAError {
    fn from(e: io::Error) -> RSAError {
        RSAError::RandomGenError(e)
    }
}

impl RSAPublicKey {
    /// Create a new `RSAPublicKey` from the given components, which you
    /// found via some other mechanism.
    pub fn new(len: usize, n: BigUint, e: BigUint) -> RSAPublicKey {
        RSAPublicKey {
            key_length: len,
            n: n,
            e: e
        }
    }

    /// Verify the signature for a given message, using the given signing hash,
    /// returning true iff the signature validates.
    pub fn verify(&self, sighash: &SigningHash, msg: &[u8], sig: Vec<u8>) -> bool {
        let hash = (sighash.run)(msg);
        let s    = o2isp(&sig);
        let m    = vp1(&self.n, &self.e, &s);
        let em   = i2osp(&m, self.key_length);
        let em_  = pkcs1_pad(&sighash.ident, &hash, self.key_length);
        (em == em_)
    }

    /// Encrypt the given data with the public key and parameters, returning
    /// the encrypted blob or an error encountered during encryption.
    ///
    /// OAEP encoding is used for this process, which requires a random number
    /// generator. This version of the function uses `OsRng`. If you want to
    /// use your own RNG, use `encrypt_w_rng`.
    pub fn encrypt<H:Clone + Input + FixedOutput>(&self, oaep: &OAEPParams<H>, msg: &[u8])
        -> Result<Vec<u8>,RSAError>
    {
        let mut g = OsRng::new()?;
        self.encrypt_with_rng(&mut g, oaep, msg)
    }

    /// Encrypt the given data with the public key and parameters, returning
    /// the encrypted blob or an error encountered during encryption. This
    /// version also allows you to provide your own RNG, if you really feel
    /// like shooting yourself in the foot.
    pub fn encrypt_with_rng<G,H>(&self, g: &mut G, oaep: &OAEPParams<H>, msg: &[u8])
        -> Result<Vec<u8>,RSAError>
      where G: Rng, H: Clone + Input + FixedOutput
    {
        if self.key_length <= ((2 * oaep.hash_len()) + 2) {
            return Err(RSAError::KeyTooSmallForHash);
        }

        let mut res = Vec::new();

        for chunk in msg.chunks(self.key_length - (2 * oaep.hash_len()) - 2) {
            let mut newchunk = self.oaep_encrypt(g, oaep, chunk)?;
            res.append(&mut newchunk)
        }

        Ok(res)
    }

    fn oaep_encrypt<G: Rng,H:Clone + Input + FixedOutput>(&self, g: &mut G, oaep: &OAEPParams<H>, msg: &[u8])
        -> Result<Vec<u8>,RSAError>
    {
        // Step 1b
        if msg.len() > (self.key_length - (2 * oaep.hash_len()) - 2) {
            return Err(RSAError::BadMessageSize)
        }
        // Step 2a
        let mut lhash = oaep.hash(oaep.label.as_bytes());
        // Step 2b
        let num0s = self.key_length - msg.len() - (2 * oaep.hash_len()) - 2;
        let mut ps = Vec::new();
        ps.resize(num0s, 0);
        // Step 2c
        let mut db = Vec::new();
        db.append(&mut lhash);
        db.append(&mut ps);
        db.push(1);
        db.extend_from_slice(msg);
        // Step 2d
        let seed : Vec<u8> = g.gen_iter().take(oaep.hash_len()).collect();
        // Step 2e
        let db_mask = oaep.mgf1(&seed, self.key_length - oaep.hash_len() - 1);
        // Step 2f
        let mut masked_db = xor_vecs(&db, &db_mask);
        // Step 2g
        let seed_mask = oaep.mgf1(&masked_db, oaep.hash_len());
        // Step 2h
        let mut masked_seed = xor_vecs(&seed, &seed_mask);
        // Step 2i
        let mut em = Vec::new();
        em.push(0);
        em.append(&mut masked_seed);
        em.append(&mut masked_db);
        // Step 3a
        let m_i = o2isp(&em);
        // Step 3b
        let c_i = ep(&self.n, &self.e, &m_i);
        // Step 3c
        let c = i2osp(&c_i, self.key_length);
        Ok(c)
    }
}

fn xor_vecs(a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a,b)| a^b).collect()
}


/// A RSA private key.
#[derive(Clone,Debug)]
pub struct RSAPrivateKey {
    key_length: usize,
    n: BigUint,
    d: BigUint
}

impl RSAPrivateKey {
    /// Generate a private key, using the given `n` and `d` parameters
    /// gathered from some other source.
    pub fn new(len: usize, n: BigUint, d: BigUint) -> RSAPrivateKey {
        RSAPrivateKey {
            key_length: len,
            n: n,
            d: d
        }
    }

    /// Sign a message using the given hash.
    pub fn sign(&self, sighash: &SigningHash, msg: &[u8]) -> Vec<u8> {
        let hash = (sighash.run)(msg);
        let em   = pkcs1_pad(&sighash.ident, &hash, self.key_length);
        let m    = o2isp(&em);
        let s    = sp1(&self.n, &self.d, &m);
        let sig  = i2osp(&s, self.key_length);
        sig
    }

    /// Decrypt a message with the given parameters.
    pub fn decrypt<H: Clone + Input + FixedOutput>(&self, oaep: &OAEPParams<H>, msg: &[u8])
        -> Result<Vec<u8>,RSAError>
    {
        let mut res = Vec::new();

        for chunk in msg.chunks(self.key_length) {
            let mut dchunk = self.oaep_decrypt(oaep, chunk)?;
            res.append(&mut dchunk);
        }

        Ok(res)
    }

    fn oaep_decrypt<H: Clone + Input + FixedOutput>(&self, oaep: &OAEPParams<H>, c: &[u8])
        -> Result<Vec<u8>,RSAError>
    {
        // Step 1b
        if c.len() != self.key_length {
            return Err(RSAError::DecryptionError);
        }
        // Step 1c
        if self.key_length < ((2 * oaep.hash_len()) + 2) {
            return Err(RSAError::DecryptHashMismatch);
        }
        // Step 2a
        let c_ip = o2isp(&c.to_vec());
        // Step 2b
        let m_ip = dp(&self.n, &self.d, &c_ip);
        // Step 2c
        let em = i2osp(&m_ip, self.key_length);
        // Step 3a
        let l_hash = oaep.hash(oaep.label.as_bytes());
        // Step 3b
        let (y, rest) = em.split_at(1);
        let (masked_seed, masked_db) = rest.split_at(oaep.hash_len());
        // Step 3c
        let seed_mask = oaep.mgf1(masked_db, oaep.hash_len());
        // Step 3d
        let seed = xor_vecs(&masked_seed.to_vec(), &seed_mask);
        // Step 3e
        let db_mask = oaep.mgf1(&seed, self.key_length - oaep.hash_len() - 1);
        // Step 3f
        let db = xor_vecs(&masked_db.to_vec(), &db_mask);
        // Step 3g
        let (l_hash2, ps_o_m) = db.split_at(oaep.hash_len());
        let o_m = drop0s(ps_o_m);
        let (o, m) = o_m.split_at(1);
        // Checks!
        if o != [1] {
            return Err(RSAError::DecryptionError);
        }
        if l_hash != l_hash2 {
            return Err(RSAError::DecryptionError);
        }
        if y != [0] {
            return Err(RSAError::DecryptionError);
        }

        Ok(m.to_vec())
    }
}

fn drop0s(a: &[u8]) -> &[u8] {
    let mut idx = 0;

    while (idx < a.len()) && (a[idx] == 0) {
        idx = idx + 1;
    }

    &a[idx..]
}

// encoding PKCS1 stuff
fn pkcs1_pad(ident: &[u8], hash: &[u8], keylen: usize) -> Vec<u8> {
    let mut idhash = Vec::new();
    idhash.extend_from_slice(ident);
    idhash.extend_from_slice(hash);
    let tlen = idhash.len();
    assert!(keylen > (tlen + 3));
    let mut padding = Vec::new();
    padding.resize(keylen - tlen - 3, 0xFF);
    let mut result = vec![0x00, 0x01];
    result.append(&mut padding);
    result.push(0x00);
    result.append(&mut idhash);
    result
}

// the RSA encryption function
fn ep(n: &BigUint, e: &BigUint, m: &BigUint) -> BigUint {
    m.modpow(e, n)
}

// the RSA decryption function
fn dp(n: &BigUint, d: &BigUint, c: &BigUint) -> BigUint {
    c.modpow(d, n)
}

// the RSA signature generation function
fn sp1(n: &BigUint, d: &BigUint, m: &BigUint) -> BigUint {
    m.modpow(d, n)
}

// the RSA signature verification function
fn vp1(n: &BigUint, e: &BigUint, s: &BigUint) -> BigUint {
    s.modpow(e, n)
}

/// Parameters for OAEP encryption and decryption: a hash function to use
/// as part of the message generation function (MGF1, if you're curious),
/// and any labels you want to include as part of the encryption.
pub struct OAEPParams<H: Clone + Input + FixedOutput> {
    pub hash: H,
    pub label: String
}

impl<H: Clone + Input + FixedOutput> OAEPParams<H> {
    pub fn new(hash: H, label: String)
        -> OAEPParams<H>
    {
        OAEPParams { hash: hash, label: label }
    }

    pub fn hash_len(&self) -> usize {
        self.hash.clone().fixed_result().as_slice().len()
    }

    pub fn hash(&self, input: &[u8]) -> Vec<u8> {
        let mut digest = self.hash.clone();
        digest.process(input);
        digest.fixed_result().as_slice().to_vec()
    }

    pub fn mgf1(&self, input: &[u8], len: usize) -> Vec<u8> {
        let mut res = Vec::with_capacity(len);
        let mut counter = Zero::zero();
        let one: BigUint = One::one();

        while res.len() < len {
            let c = i2osp(&counter, 4);
            let mut digest = self.hash.clone();
            digest.process(input);
            digest.process(&c);
            let chunk = digest.fixed_result();
            res.extend_from_slice(chunk.as_slice());
            counter = counter + &one;
        }

        res.truncate(len);
        res
    }
}

#[cfg(test)]
mod tests {
    use quickcheck::{Arbitrary,Gen};
    use sha2::Sha224;
    use super::*;

    const TEST_KEY_SIZES: [usize; 2] = [512, 1024];

    #[derive(Clone,Debug)]
    struct KeyPairAndNum {
        kp: RSAKeyPair,
        n: BigUint
    }

    impl Arbitrary for KeyPairAndNum {
        fn arbitrary<G: Gen>(g: &mut G) -> KeyPairAndNum {
            let size = g.choose(&TEST_KEY_SIZES).unwrap();
            let kp = RSAKeyPair::generate_w_rng(g, *size).unwrap();
            let bytes: Vec<u8> = g.gen_iter().take(size / 8).collect();
            let n = BigUint::from_bytes_be(&bytes);
            KeyPairAndNum{ kp: kp, n: n }
        }
    }

    quickcheck! {
        fn rsa_ep_dp_inversion(kpv: KeyPairAndNum) -> bool {
            let m = kpv.n % &kpv.kp.public.n;
            let ciphertext = ep(&kpv.kp.public.n, &kpv.kp.public.e, &m);
            let mprime = dp(&kpv.kp.private.n, &kpv.kp.private.d, &ciphertext);
            mprime == m
        }

        fn rsa_sp_vp_inversion(kpv: KeyPairAndNum) -> bool {
            let m = kpv.n % &kpv.kp.public.n;
            let sig = sp1(&kpv.kp.private.n, &kpv.kp.private.d, &m);
            let mprime = vp1(&kpv.kp.public.n, &kpv.kp.public.e, &sig);
            mprime == m
        }
    }

    #[derive(Clone,Debug)]
    struct Message {
        m: Vec<u8>
    }

    impl Arbitrary for Message {
        fn arbitrary<G: Gen>(g: &mut G) -> Message {
            let len = 1 + (g.gen::<u8>() % 3);
            let mut storage = Vec::new();
            for _ in 0..len {
                storage.push(g.gen::<u8>());
            }
            Message{ m: storage }
        }
    }

    #[derive(Clone,Debug)]
    struct KeyPairAndSigHash {
        kp: RSAKeyPair,
        sh: &'static SigningHash
    }

    impl Arbitrary for KeyPairAndSigHash {
        fn arbitrary<G: Gen>(g: &mut G) -> KeyPairAndSigHash {
            let size = g.choose(&TEST_KEY_SIZES).unwrap();
            let kp = RSAKeyPair::generate_w_rng(g, *size).unwrap();
            let hash = if *size == 1024 {
                let hashes = [&SIGNING_HASH_SHA1, &SIGNING_HASH_SHA224];
                g.choose(&hashes).unwrap().clone()
            } else {
                let hashes = [&SIGNING_HASH_SHA1, &SIGNING_HASH_SHA224,
                              &SIGNING_HASH_SHA256];
                g.choose(&hashes).unwrap().clone()
            };
            KeyPairAndSigHash{ kp: kp, sh: hash }
        }
    }

    quickcheck! {
        fn rsa_sign_verifies(kpsh: KeyPairAndSigHash, m: Message)
            -> bool
        {
            let sig = kpsh.kp.private.sign(kpsh.sh, &m.m);
            kpsh.kp.public.verify(kpsh.sh, &m.m, sig)
        }

        fn rsa_enc_dec_roundtrips(skp: KeyPairAndNum, m: Message) -> bool {
            let oaep = OAEPParams {
                hash: Sha224::default(),
                label: "test".to_string()
            };
            let c = skp.kp.public.encrypt(&oaep, &m.m).unwrap();
            let mp = skp.kp.private.decrypt(&oaep, &c).unwrap();

            mp == m.m
        }
    }
}
