use super::super::chips::hash_v2::{Hash2Chip, Hash2Config};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::{circuit::*, plonk::*};
use snark_verifier_sdk::CircuitExt;

#[derive(Default)]
struct Hash2Circuit<Fp> {
    pub a: Fp,
    pub b: Fp,
}

impl CircuitExt<Fp> for Hash2Circuit<Fp> {
    fn num_instance(&self) -> Vec<usize> {
        vec![1]
    }

    fn instances(&self) -> Vec<Vec<Fp>> {
        vec![vec![self.a + self.b]]
    }
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
        let a = chip.load_private(layouter.namespace(|| "load a"), Value::known(self.a))?;
        let b = chip.load_private(layouter.namespace(|| "load b"), Value::known(self.b))?;
        let c = chip.hash(layouter.namespace(|| "load row"), a, b.clone())?;
        chip.expose_public(layouter.namespace(|| "hash output check"), &c, 0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Hash2Circuit;
    // use crate::circuits::utils::{evm_verify, gen_evm_verifier, gen_proof};
    use ark_std::{end_timer, start_timer};
    use halo2_proofs::circuit;
    use halo2_proofs::plonk::{keygen_pk, keygen_vk, Circuit};
    use halo2_proofs::poly::commitment::Params;
    use halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr as Fp},
        poly::kzg::commitment::ParamsKZG,
    };
    use snark_verifier_sdk::CircuitExt;
    use snark_verifier_sdk::SHPLONK;
    use snark_verifier_sdk::{
        evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk},
        gen_pk,
        halo2::{aggregation::AggregationCircuit, gen_snark_shplonk, gen_srs},
        Snark,
    };
    use std::fs::File;
    use std::path::Path;

    fn gen_application_snark(params: &ParamsKZG<Bn256>) -> Snark {
        let a = Fp::from(2);
        let b = Fp::from(7);

        // let circuit = Hash2Circuit::default();

        let circuit_b = Hash2Circuit { a, b };

        let prover = MockProver::run(4, &circuit_b, circuit_b.instances()).unwrap();

        assert_eq!(prover.verify(), Ok(()));

        let vk = keygen_vk(params, &circuit_b).unwrap();
        let pk = keygen_pk(params, vk, &circuit_b).unwrap();

        // if I pass circuit to gen_snark_shplonk, it fails...
        gen_snark_shplonk(params, &pk, circuit_b, None::<&str>)
    }

    #[test]
    fn test_hash_2() {
        let k = 4;

        // successful case
        let a = Fp::from(2);
        let b = Fp::from(7);
        let public_inputs = vec![Fp::from(9), Fp::from(7)];
        let circuit = Hash2Circuit { a, b };
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // failure case
        let public_inputs = vec![Fp::from(8)];
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_hash_2_aggregation() {
        let k = 4;
        let params_app = gen_srs(k);

        let snarks = [(); 3].map(|_| gen_application_snark(&params_app));

        let ptau_path = format!("ptau/hermez-raw-{}", 22);
        let mut params_fs = File::open(ptau_path).expect("couldn't load params");
        let params = ParamsKZG::<Bn256>::read(&mut params_fs).expect("Failed to read params");

        let agg_circuit = AggregationCircuit::<SHPLONK>::new(&params, snarks);

        // Generating artifacts for the agg circuit
        let start0 = start_timer!(|| "gen vk & pk");
        let pk = gen_pk(
            &params,
            &agg_circuit.without_witnesses(),
            Some(Path::new("./examples/agg.pk")),
        );
        end_timer!(start0);

        std::fs::remove_file("./examples/agg.snark").unwrap_or_default();
        let _snark = gen_snark_shplonk(
            &params,
            &pk,
            agg_circuit.clone(),
            Some(Path::new("./examples/agg.snark")),
        );

        let num_instances = agg_circuit.num_instance();
        let instances = agg_circuit.instances();
        let proof_calldata = gen_evm_proof_shplonk(&params, &pk, agg_circuit, instances.clone());

        let deployment_code = gen_evm_verifier_shplonk::<AggregationCircuit<SHPLONK>>(
            &params,
            pk.get_vk(),
            num_instances,
            Some(Path::new("./examples/standard_plonk.yul")),
        );

        evm_verify(deployment_code, instances, proof_calldata);
    }
}
