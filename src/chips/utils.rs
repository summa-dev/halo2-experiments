use std::str::FromStr;

use halo2_proofs::circuit::*;
use halo2_proofs::halo2curves::pasta::Fp;
use num_bigint::BigUint;
use halo2_proofs::plonk::Expression;

fn parse_hex(hex_asm: &str) -> Vec<u8> {
    let mut hex_bytes = hex_asm
        .as_bytes()
        .iter()
        .filter_map(|b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        })
        .fuse();

    let mut bytes = Vec::new();
    while let (Some(h), Some(l)) = (hex_bytes.next(), hex_bytes.next()) {
        bytes.push(h << 4 | l)
    }
    bytes
}

pub fn value_fp_to_big_uint(v: Value<Fp>) -> BigUint {
    let mut sum = Fp::zero();
    v.as_ref().map(|f| sum = sum.add(f));
    to_uint(sum)
}

pub fn fp_to_big_uint(value: &Fp) -> BigUint {
    let mut sum = Fp::zero();
    sum = sum.add(value);
    to_uint(sum)
}

pub fn fp_to_nbits<const N: usize>(value: &Fp) -> (Fp, Fp) {
    let max_bits = Fp::from(1 << N);
    let mut remains = value.clone();
    let mut accumulator = Fp::zero();
    while remains >= max_bits {
        remains = remains.sub(&max_bits);
        accumulator = accumulator.add(&Fp::one());
    }
    (accumulator, remains)
}

pub fn add_carry<const MAX_BITS: usize>(
    value: Value<Fp>,
    hi: AssignedCell<Fp, Fp>,
    lo: AssignedCell<Fp, Fp>,
) -> (Fp, Fp) {
    let mut sum = Fp::zero();

    // sum of all values
    value.as_ref().map(|f| sum = sum.add(f));
    hi.value().map(|f| sum = sum.add(&f.mul(&Fp::from(1 << MAX_BITS))));
    lo.value().map(|f| sum = sum.add(f));

    // Iterate sum of all
    fp_to_nbits::<MAX_BITS>(&sum)
}

fn to_uint(sum: Fp) -> BigUint {
  let sum_str = format!("{:?}", sum);
  let (_, splited_sum_str) = sum_str.split_at(2); // remove '0x'

  BigUint::from_bytes_be(parse_hex(splited_sum_str).as_slice())
}

pub fn range_check_vec(
    selector: &Expression<Fp>,
    value_vec: Vec<Expression<Fp>>,
    range: usize,
) -> Vec<Expression<Fp>> {
    let mut exprs: Vec<Expression<Fp>> = vec![];
    for w in value_vec {
        let w_expr = (1..range).fold(w.clone(), |acc, i| {
            acc * (Expression::Constant(Fp::from(i as u64)) - w.clone())
        });
        exprs.push(selector.clone() * w_expr);
    }
    exprs
}

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
