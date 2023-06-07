use super::super::chips::hash_v2::{Hash2Chip, Hash2Config};
use halo2_proofs::halo2curves::bn256::Fr as Fp;

use halo2_proofs::{circuit::*, plonk::*};

#[derive(Default)]
struct Hash2Circuit<Fp> {
    pub a: Value<Fp>,
    pub b: Value<Fp>,
}

impl Circuit<Fp> for Hash2Circuit<Fp> {
    type Config = Hash2Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let instance = meta.instance_column();

        Hash2Chip::configure(meta, [col_a, col_b, col_c], instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = Hash2Chip::construct(config);
        let a = chip.load_private(layouter.namespace(|| "load a"), self.a)?;
        let b = chip.load_private(layouter.namespace(|| "load b"), self.b)?;
        let c = chip.hash(layouter.namespace(|| "load row"), a, b.clone())?;
        chip.expose_public(layouter.namespace(|| "hash output check"), &c, 0)?;
        chip.expose_public(layouter.namespace(|| "b check"), &b, 1)?;
        // chip.expose_public(layouter.namespace(|| "a check"), &a, 2)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Hash2Circuit;
    use crate::circuits::utils::{evm_verify, gen_evm_verifier, gen_proof};
    use halo2_proofs::plonk::{keygen_pk, keygen_vk};
    use halo2_proofs::{
        circuit::Value,
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr as Fp},
        poly::kzg::commitment::ParamsKZG,
    };
    use rand::rngs::OsRng;

    #[test]
    fn test_hash_2() {
        let k = 4;

        // successful case
        let a = Value::known(Fp::from(2));
        let b = Value::known(Fp::from(7));
        let public_inputs = vec![Fp::from(9)];
        let circuit = Hash2Circuit { a, b };
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // failure case
        let public_inputs = vec![Fp::from(8)];
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_hash_2_on_chain() {
        let k = 4;
        let a = Value::known(Fp::from(2));
        let b = Value::known(Fp::from(7));
        let circuit = Hash2Circuit { a, b };

        let params = ParamsKZG::<Bn256>::setup(k, OsRng);

        let vk = keygen_vk(&params, &circuit).unwrap();

        let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();

        let deployment_code = gen_evm_verifier(&params, &vk, vec![2]);

        let instances = vec![vec![Fp::from(9), Fp::from(7)]];

        let proof = gen_proof(&params, &pk, circuit, instances.clone());

        evm_verify(deployment_code, instances, proof);
    }
}
