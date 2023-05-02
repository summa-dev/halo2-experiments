use eth_types::Field;

use halo2_proofs::circuit::*;
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

pub fn value_f_to_big_uint<F: Field>(v: Value<F>) -> BigUint {
    let mut sum = F::zero();
    v.as_ref().map(|f| sum = sum.add(f));
    to_uint(sum)
}

pub fn f_to_big_uint<F: Field>(value: &F) -> BigUint {
    let mut sum = F::zero();
    sum = sum.add(value);
    to_uint(sum)
}

pub fn f_to_nbits<const N: usize, F: Field>(value: &F) -> (F, F) {
    let max_bits = F::from(1 << N);
    let mut remains = value.clone();
    let mut accumulator = F::zero();
    while remains >= max_bits {
        remains = remains.sub(&max_bits);
        accumulator = accumulator.add(&F::one());
    }
    (accumulator, remains)
}

pub fn add_carry<const MAX_BITS: usize, F: Field>(
    value: Value<F>,
    hi: AssignedCell<F, F>,
    lo: AssignedCell<F, F>,
) -> (F, F) {
    let mut sum = F::zero();

    // sum of all values
    value.as_ref().map(|f| sum = sum.add(f));
    hi.value().map(|f| sum = sum.add(&f.mul(&F::from(1 << MAX_BITS))));
    lo.value().map(|f| sum = sum.add(f));

    // Iterate sum of all
    f_to_nbits::<MAX_BITS, F>(&sum)
}

fn to_uint<F: Field>(sum: F) -> BigUint {
  let sum_str = format!("{:?}", sum);
  let (_, splited_sum_str) = sum_str.split_at(2); // remove '0x'

  BigUint::from_bytes_be(parse_hex(splited_sum_str).as_slice())
}

pub fn range_check_vec<F: Field>(
    selector: &Expression<F>,
    value_vec: Vec<Expression<F>>,
    range: usize,
) -> Vec<Expression<F>> {
    let mut exprs: Vec<Expression<F>> = vec![];
    for w in value_vec {
        let w_expr = (1..range).fold(w.clone(), |acc, i| {
            acc * (Expression::Constant(F::from(i as u64)) - w.clone())
        });
        exprs.push(selector.clone() * w_expr);
    }
    exprs
}

pub fn decompose_bigInt_to_ubits<F: Field>(
  e: &BigUint,
  number_of_limbs: usize,
  bit_len: usize,
) -> Vec<F> {
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
              F::from(limb)
          }
          core::cmp::Ordering::Equal => {
              let limb = u64_digit & mask;
              u64_digit = e.next().unwrap_or(0);
              rem = 64;
              F::from(limb)
          }
          core::cmp::Ordering::Less => {
              let mut limb = u64_digit;
              u64_digit = e.next().unwrap_or(0);
              limb |= (u64_digit & ((1 << (bit_len - rem)) - 1)) << rem; // *
              u64_digit >>= bit_len - rem;
              rem += 64 - bit_len;
              F::from(limb)
          }
      })
      .collect()
}
