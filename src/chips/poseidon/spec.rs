use crate::chips::poseidon::rate2_params;
use halo2_gadgets::poseidon::primitives::*;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::halo2curves::bn256::Fr as Fp;

// P128Pow5T3 is the default Spec provided by the Halo2 Gadget => https://github.com/privacy-scaling-explorations/halo2/blob/main/halo2_gadgets/src/poseidon/primitives/p128pow5t3.rs#L13
// This spec hardcodes the WIDTH and RATE parameters of the hash function to 3 and 2 respectively
// This is problematic because to perform an hash of a input array of length 4, we need the WIDTH parameter to be higher than 3
// Since the WIDTH parameter is used to define the number of hash_inputs column in the PoseidonChip.
// Because of that we need to define a new Spec
// MySpec struct allows us to define the parameters of the Poseidon hash function WIDTH and RATE
#[derive(Debug, Clone, Copy)]
pub struct Spec2;

impl Spec<Fp, 3, 2> for Spec2 {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        57
    }

    fn sbox(val: Fp) -> Fp {
        val.pow_vartime(&[5])
    }

    fn secure_mds() -> usize {
        unimplemented!()
    }

    fn constants() -> (Vec<[Fp; 3]>, Mds<Fp, 3>, Mds<Fp, 3>) {
        (
            rate2_params::ROUND_CONSTANTS[..].to_vec(),
            rate2_params::MDS,
            rate2_params::MDS_INV,
        )
    }
}
