use super::super::chips::hash_v1::{Hash1Chip, Hash1Config};

use halo2_proofs::halo2curves::bn256::Fr as Fp;

use halo2_proofs::{circuit::*, plonk::*};

pub struct Hash1Circuit {
    pub a: Value<Fp>,
}

impl Default for Hash1Circuit {
    fn default() -> Self {
        Self {
            a: Value::unknown(),
        }
    }
}

impl Circuit<Fp> for Hash1Circuit {
    type Config = Hash1Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let instance = meta.instance_column();

        Hash1Chip::configure(meta, [col_a, col_b], instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = Hash1Chip::construct(config);
        chip.assign_advice_row(layouter.namespace(|| "load row"), self.a)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Hash1Circuit;
    use crate::circuits::utils::{evm_verify, gen_evm_verifier, gen_proof};
    use halo2_proofs::plonk::{keygen_pk, keygen_vk};
    use halo2_proofs::{
        circuit::Value,
        halo2curves::bn256::{Bn256, Fr as Fp},
        poly::kzg::commitment::ParamsKZG,
    };
    use rand::rngs::OsRng;

    #[test]
    fn test_hash_1_on_chain() {
        let k = 4;
        let a = Value::known(Fp::from(2));
        let circuit = Hash1Circuit { a };

        let params = ParamsKZG::<Bn256>::setup(k, OsRng);

        let vk = keygen_vk(&params, &circuit).unwrap();

        let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();

        let num_instance = vec![1];

        let deployment_code = gen_evm_verifier(&params, &vk, num_instance);

        let instances = vec![vec![Fp::from(4)]];

        let proof = gen_proof(&params, &pk, circuit, instances.clone());

        evm_verify(deployment_code, instances, proof);
    }
}
