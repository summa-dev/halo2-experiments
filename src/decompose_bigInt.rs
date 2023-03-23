use halo2curves::{ff::PrimeField, pasta::*};
use num_bigint::BigUint;

pub fn decompose_bigInt_to_ubits(
    e: &BigUint,
    number_of_limbs: usize,
    bit_len: usize,
) -> Vec<Fp> {
    debug_assert!(bit_len <= 64);

    let mut e = e.iter_u64_digits();
    let mask: u64 = (1u64 << bit_len) - 1u64;
    let mut u64_digit = e.next().unwrap_or(0);
    let mut rem = 64;
    (0..number_of_limbs)
        .map(|_| match rem.cmp(&bit_len) {
            core::cmp::Ordering::Greater => {
                let limb = u64_digit & mask;
                u64_digit >>= bit_len;
                rem -= bit_len;
                Fp::from(limb)
            }
            core::cmp::Ordering::Equal => {
                let limb = u64_digit & mask;
                u64_digit = e.next().unwrap_or(0);
                rem = 64;
                Fp::from(limb)
            }
            core::cmp::Ordering::Less => {
                let mut limb = u64_digit;
                u64_digit = e.next().unwrap_or(0);
                limb |= (u64_digit & ((1 << (bit_len - rem)) - 1)) << rem; // *
                u64_digit >>= bit_len - rem;
                rem += 64 - bit_len;
                Fp::from(limb)
            }
        })
        .collect()
}

pub fn decompose_biguint_u64(e: &BigUint, num_limbs: usize, bit_len: usize) -> Vec<Fp> {
    debug_assert!(bit_len > 64 && bit_len <= 128);
    let mut e = e.iter_u64_digits();

    let mut limb0 = e.next().unwrap_or(0) as u128;
    let mut rem = bit_len - 64;
    let mut u64_digit = e.next().unwrap_or(0);
    limb0 |= ((u64_digit & ((1 << rem) - 1)) as u128) << 64;
    u64_digit >>= rem;
    rem = 64 - rem;

    core::iter::once(Fp::from_u128(limb0))
        .chain((1..num_limbs).map(|_| {
            let mut limb: u128 = u64_digit.into();
            let mut bits = rem;
            u64_digit = e.next().unwrap_or(0);
            if bit_len - bits >= 64 {
                limb |= (u64_digit as u128) << bits;
                u64_digit = e.next().unwrap_or(0);
                bits += 64;
            }
            rem = bit_len - bits;
            limb |= ((u64_digit & ((1 << rem) - 1)) as u128) << bits;
            u64_digit >>= rem;
            rem = 64 - rem;
            Fp::from_u128(limb)
        }))
        .collect()
}

mod tests {
    use super::*;
    use halo2curves::pasta::Fp;
    use num_bigint::BigUint;

    #[test]
    fn test_decompose_bigInt_toU64() {
        let a = BigUint::new(vec![u32::MAX, u32::MAX - 1]);
        let decom = decompose_biguint_u64(&a, 3, 65);
        // println!("decomposed a: {:?}", decom);
        assert_eq!(decom[0], Fp::from(u64::MAX - 1));
    }

    #[test]
    fn test_decompose_bigInt_to_u16() {
        let b = BigUint::new(vec![u32::MAX, u32::MAX]);
        let decom = decompose_bigInt_to_ubits(&b, 12, 16);
        // println!("decompose_Fps: {:?}", decom);
        assert_eq!(decom[0], Fp::from(65535));
        assert_eq!(decom[1], Fp::from(65535));
        assert_eq!(decom[2], Fp::from(65535));
        assert_eq!(decom[3], Fp::from(65535));
        assert_eq!(decom[4], Fp::zero());
    }
}
