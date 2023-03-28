use super::super::chips::hash_v2::{
    Hash2Config, Hash2Chip
};

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::*,
    plonk::*
};

#[derive(Default)]
struct Hash2Circuit<F> {
    pub a: Value<F>,
    pub b: Value<F>,
}

impl<F: FieldExt> Circuit<F> for Hash2Circuit<F> {

    type Config = Hash2Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let hash_selector = meta.selector();
        let instance = meta.instance_column();

        Hash2Chip::configure(meta, [col_a, col_b, col_c], hash_selector, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = Hash2Chip::construct(config);
        let a = chip.load_private(layouter.namespace(|| "load a"), self.a)?;
        let b = chip.load_private(layouter.namespace(|| "load b"), self.b)?;
        let c = chip.hash(layouter.namespace(|| "load row"), a, b)?;
        chip.expose_public(layouter.namespace(|| "hash output check"), &c, 0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Hash2Circuit;
    use halo2_proofs::{
        circuit::Value,
        dev::MockProver,
        halo2curves::pasta::Fp
    };

    #[test]
    fn test_hash_2() {
        let k = 4;

        // successful case
        let a = Value::known(Fp::from(2));
        let b = Value::known(Fp::from(7));
        let public_inputs = vec![Fp::from(9)];
        let circuit = Hash2Circuit { a, b };
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // failure case
        let public_inputs = vec![Fp::from(8)];
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        assert!(prover.verify().is_err());
    }
}

