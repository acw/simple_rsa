use num::bigint::Sign;
use num::{BigInt,BigUint,Integer,One,Signed,Zero};
use rand::Rng;
use std::ops::Neg;

static ACCEPTABLE_KEY_SIZES: [(usize,usize); 8] =
    [(512,   7),
     (1024,  7),
     (2048,  4),
     (3072,  3),
     (4096,  3),
     (7680,  3),
     (8192,  3),
     (15360, 3)];

static U32_SMALL_PRIMES: [u32; 310] = [
      2,     3,     5,     7,    11,    13,    17,    19,    23,    29,
     31,    37,    41,    43,    47,    53,    59,    61,    67,    71,
     73,    79,    83,    89,    97,   101,   103,   107,   109,   113,
    127,   131,   137,   139,   149,   151,   157,   163,   167,   173,
    179,   181,   191,   193,   197,   199,   211,   223,   227,   229,
    233,   239,   241,   251,   257,   263,   269,   271,   277,   281,
    283,   293,   307,   311,   313,   317,   331,   337,   347,   349,
    353,   359,   367,   373,   379,   383,   389,   397,   401,   409,
    419,   421,   431,   433,   439,   443,   449,   457,   461,   463,
    467,   479,   487,   491,   499,   503,   509,   521,   523,   541,
    547,   557,   563,   569,   571,   577,   587,   593,   599,   601,
    607,   613,   617,   619,   631,   641,   643,   647,   653,   659,
    661,   673,   677,   683,   691,   701,   709,   719,   727,   733,
    739,   743,   751,   757,   761,   769,   773,   787,   797,   809,
    811,   821,   823,   827,   829,   839,   853,   857,   859,   863,
    877,   881,   883,   887,   907,   911,   919,   929,   937,   941,
    947,   953,   967,   971,   977,   983,   991,   997,  1009,  1013,
   1019,  1021,  1031,  1033,  1039,  1049,  1051,  1061,  1063,  1069,
   1087,  1091,  1093,  1097,  1103,  1109,  1117,  1123,  1129,  1151,
   1153,  1163,  1171,  1181,  1187,  1193,  1201,  1213,  1217,  1223,
   1229,  1231,  1237,  1249,  1259,  1277,  1279,  1283,  1289,  1291,
   1297,  1301,  1303,  1307,  1319,  1321,  1327,  1361,  1367,  1373,
   1381,  1399,  1409,  1423,  1427,  1429,  1433,  1439,  1447,  1451,
   1453,  1459,  1471,  1481,  1483,  1487,  1489,  1493,  1499,  1511,
   1523,  1531,  1543,  1549,  1553,  1559,  1567,  1571,  1579,  1583,
   1597,  1601,  1607,  1609,  1613,  1619,  1621,  1627,  1637,  1657,
   1663,  1667,  1669,  1693,  1697,  1699,  1709,  1721,  1723,  1733,
   1741,  1747,  1753,  1759,  1777,  1783,  1787,  1789,  1801,  1811,
   1823,  1831,  1847,  1861,  1867,  1871,  1873,  1877,  1879,  1889,
   1901,  1907,  1913,  1931,  1933,  1949,  1951,  1973,  1979,  1987,
   1993,  1997,  1999,  2003,  2011,  2017,  2027,  2029,  2039,  2053];

lazy_static! {
    static ref SMALL_PRIMES: Vec<BigUint> = {
        U32_SMALL_PRIMES.iter().map(|x| BigUint::from(*x)).collect()
    };
}

pub fn generate_pq<G: Rng>(rng: &mut G, e: &BigUint, bitlen: usize)
    -> Option<(BigUint,BigUint)>
{
    let iterations = get_iterations(bitlen)?;
    let sqrt2_32: u64 = 6074001000;
    let one: BigUint = One::one();
    let minval: BigUint = BigUint::from(sqrt2_32) << ((bitlen/2) - 33);
    let mindiff: BigUint = one << ((bitlen/2)-101);
    let p = generate_prime(rng, e, &minval, bitlen / 2, iterations);

    loop {
        let q = generate_prime(rng, e, &minval, bitlen / 2, iterations);

        if diff(&p, &q) >= mindiff {
            return Some((p, q));
        }
    }
}

fn generate_prime<G: Rng>(rng: &mut G,
                          e: &BigUint,
                          min: &BigUint,
                          bitlen: usize,
                          iterations: usize)
    -> BigUint
{
    let one: BigUint = One::one();
    let topbit       = &one << (bitlen - 1);

    loop {
        let base       = random_number(rng, bitlen);
        let candidate  = base | &topbit | &one;

        // This must be bigger than our minimum value.
        if &candidate < min {
            continue;
        }
        // The GCD of this and e must be 1.
        if !gcd_is_one(&e, &candidate) {
            continue;
        }
        // And it must probably be prime.
        if probably_prime(rng, &candidate, iterations) {
            return candidate;
        }
    }
}

fn probably_prime<G: Rng>(g: &mut G, w: &BigUint, iters: usize)
    -> bool
{
    // quick test against the small primes
    for tester in SMALL_PRIMES.iter() {
        if w.is_multiple_of(&tester) {
            return false;
        }
    }
    // and then off to Miller-Rabin
    miller_rabin(g, w, iters)
}

fn miller_rabin<G: Rng>(g: &mut G, n: &BigUint, iters: usize)
    -> bool
{
    let one: BigUint = One::one();
    let two = &one + &one;
    let nm1 = n - &one;
    // Quoth Wikipedia:
    // write n - 1 as 2^r*d with d odd by factoring powers of 2 from n - 1
    let mut d = nm1.clone();
    let mut r = 0;
    while d.is_even() {
        d >>= 1;
        r += 1;
        assert!(r < n.bits());
    }
    // WitnessLoop: repeat k times
    'WitnessLoop: for _k in 0..iters {
        // pick a random integer a in the range [2, n - 2]
        let a = random_in_range(g, &two, &nm1);
        // x <- a^d mod n
        let mut x = a.modpow(&d, &n);
        // if x = 1 or x = n - 1 then
        if (&x == &one) || (&x == &nm1) {
            // continue WitnessLoop
            continue 'WitnessLoop;
        }
        // repeat r - 1 times:
        for _i in 0..r {
            // x <- x^2 mod n
            x = x.modpow(&two, &n);
            // if x = 1 then
            if &x == &one {
                // return composite
                return false;
            }
            // if x = n - 1 then
            if &x == &nm1 {
                // continue WitnessLoop
                continue 'WitnessLoop;
            }
        }
        // return composite
        return false;
    }
    // return probably prime
    true
}

fn diff(a: &BigUint, b: &BigUint) -> BigUint {
    if a > b {
        a - b
    } else {
        b - a
    }
}

// convert an integer into series of bytes
pub fn i2osp(x: &BigUint, len: usize) -> Vec<u8> {
    let mut base = x.to_bytes_be();

    // If the length is too long, panic
    if base.len() > len {
        panic!("Not enough room to encode integer.");
    }

    let missing = len - base.len();
    let mut result = Vec::with_capacity(len);
    result.resize(missing, 0);
    result.append(&mut base);
    result
}

// convert a series of bytes into a number
pub fn o2isp(x: &Vec<u8>) -> BigUint {
    BigUint::from_bytes_be(&x)
}

// fast modular inverse
pub fn modinv(e: &BigUint, phi: &BigUint) -> BigUint {
    let (_, mut x, _) = extended_euclidean(&e, &phi);
    let int_phi = BigInt::from_biguint(Sign::Plus, phi.clone());
    while x.is_negative() {
        x = x + &int_phi;
    }
    x.to_biguint().unwrap()
}

fn extended_euclidean(a: &BigUint, b: &BigUint) -> (BigInt, BigInt, BigInt) {
    let pos_int_a = BigInt::from_biguint(Sign::Plus, a.clone());
    let pos_int_b = BigInt::from_biguint(Sign::Plus, b.clone());
    let (d, x, y) = egcd(pos_int_a, pos_int_b);

    if d.is_negative() {
        (d.neg(), x.neg(), y.neg())
    } else {
        (d, x, y)
    }
}

fn egcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    let mut s: BigInt = Zero::zero();
    let mut old_s     = One::one();
    let mut t: BigInt = One::one();
    let mut old_t     = Zero::zero();
    let mut r         = b.clone();
    let mut old_r     = a.clone();

    while !r.is_zero() {
        let quotient = old_r.clone() / r.clone();

        let prov_r = r.clone();
        let prov_s = s.clone();
        let prov_t = t.clone();

        r = old_r - (r * &quotient);
        s = old_s - (s * &quotient);
        t = old_t - (t * &quotient);

        old_r = prov_r;
        old_s = prov_s;
        old_t = prov_t;
    }

    (old_r, old_s, old_t)
}

fn gcd_is_one(a: &BigUint, b: &BigUint) -> bool {
    let mut u = a.clone();
    let mut v = b.clone();

    if u.is_zero() {
        return v == One::one();
    }

    if v.is_zero() {
        return u == One::one();
    }

    if u.is_even() && v.is_even() {
        return false;
    }

    while u.is_even() {
        u >>= 1;
    }

    loop {
        while v.is_even() {
            v >>= 1;
        }
        // u and v guaranteed to be odd right now.
        if u > v {
            // make sure that v > u, so that our subtraction works
            // out.
            let t = u;
            u = v;
            v = t;
        }
        v = v - &u;

        if v.is_zero() {
            return u == One::one();
        }
    }
}

fn random_in_range<G: Rng>(rng: &mut G, min: &BigUint, max: &BigUint)
    -> BigUint
{
    let bitlen = ((max.bits() + 31) / 32) * 32;
    loop {
        let candidate = random_number(rng, bitlen);

        if (&candidate >= min) && (&candidate < max) {
            return candidate;
        }
    }
}

fn random_number<G: Rng>(rng: &mut G, bitlen: usize) -> BigUint {
    assert!(bitlen % 32 == 0);
    let wordlen = bitlen / 32;
    let components = rng.gen_iter().take(wordlen).collect();
    BigUint::new(components)
}

fn get_iterations(l: usize) -> Option<usize> {
    for &(m, i) in ACCEPTABLE_KEY_SIZES.iter() {
        if m == l {
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use quickcheck::{Arbitrary,Gen};
    use rand::OsRng;
    use super::*;

    #[derive(Clone,Debug)]
    struct WrappedUint {
        n: BigUint
    }

    impl Arbitrary for WrappedUint {
        fn arbitrary<G: Gen>(g: &mut G) -> WrappedUint {
            let len = g.gen::<u8>();
            let stream = g.gen_iter::<u32>();
            let contents = stream.take(len as usize).collect();
            let uint = BigUint::new(contents);
            WrappedUint{ n: uint }
        }
    }

    quickcheck! {
        fn better_gcd_works(a: WrappedUint, b: WrappedUint) -> bool {
            let myanswer = gcd_is_one(&a.n, &b.n);
            let theiranswer = a.n.gcd(&b.n) == One::one();
            myanswer == theiranswer
        }
    }

    #[derive(Clone,Debug)]
    struct KeySize {
        n: usize
    }

    impl Arbitrary for KeySize {
        fn arbitrary<G: Gen>(g: &mut G) -> KeySize {
            let &(n, _) = g.choose(&ACCEPTABLE_KEY_SIZES).unwrap();
            KeySize{ n: n }
        }
    }

    #[derive(Clone,Debug)]
    struct PositiveSizedUint {
        n: BigUint,
        s: usize // in bits!
    }

    impl Arbitrary for PositiveSizedUint {
        fn arbitrary<G: Gen>(g: &mut G) -> PositiveSizedUint {
            let base_n = WrappedUint::arbitrary(g).n;
            let size = KeySize::arbitrary(g).n;
            let one : BigUint = One::one();
            let modamt = one << size;
            let n = base_n % modamt;
            PositiveSizedUint { n: n, s: size }
        }
    }

    #[derive(Clone,Debug)]
    struct SizedBytes {
        b: Vec<u8>,
        s: usize // in bits!
    }

    impl Arbitrary for SizedBytes {
        fn arbitrary<G: Gen>(g: &mut G) -> SizedBytes {
            let size = KeySize::arbitrary(g).n;
            let bytes = g.gen_iter().take(size / 8).collect();
            SizedBytes{ b: bytes, s: size }
        }
    }

    quickcheck! {
        fn i2o2i_works(n: PositiveSizedUint) -> bool {
            let bytes = i2osp(&n.n, n.s / 8);
            let newn  = o2isp(&bytes);
            newn == n.n
        }

        fn o2i2o_works(v: SizedBytes) -> bool {
            let n = o2isp(&v.b);
            let newv = i2osp(&n, v.s / 8);
            newv == v.b
        }
    }

    #[test]
    fn miller_rabin_works() {
        let mut rng = OsRng::new().unwrap();

        assert_eq!(probably_prime(&mut rng, &bignum(18446744073709551557), 5), true);
        assert_eq!(probably_prime(&mut rng, &bignum(18446744073709551553), 5), false);
    }

    fn bignum(v: u64) -> BigUint {
        BigUint::from(v)
    }

    #[test]
    fn canget() {
        let mut rng = OsRng::new().unwrap();
        let e32: u32 = 65537;
        let e = BigUint::from(e32);
        loop {
            match generate_pq(&mut rng, &e, 512) {
                None =>
                    continue,
                Some((p, q)) => {
                    let one: BigUint = One::one();
                    let minval = one << 255;
                    assert!(p > minval);
                    assert!(q > minval);
                    assert!(p != q);
                    assert!(p.is_odd());
                    assert!(q.is_odd());
                    break;
                }
            }
        }
    }

    #[derive(Clone,Debug)]
    struct ComboPQ {
        p: BigUint,
        q: BigUint
    }

    impl Arbitrary for ComboPQ {
        fn arbitrary<G: Gen>(g: &mut G) -> ComboPQ {
            loop {
                let e32: u32 = 65537;
                let e = BigUint::from(e32);
                match generate_pq(g, &e, 512) {
                    None =>
                        continue,
                    Some((p, q)) =>
                        return ComboPQ{ p: p, q: q }
                }
            }
        }
    }

    quickcheck! {
        fn modinv_works(pq: ComboPQ) -> bool {
            let one = One::one();
            let e32: u32 = 65537;
            let e = BigUint::from(e32);
            let phi = (pq.p - &one) * (pq.q - &one);
            let d = modinv(&e, &phi);
            (e * d) % phi == one
        }
    }
}
