use super::super::chips::hash_v1::{Hash1Chip, Hash1Config};

use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*};

#[derive(Default)]
struct Hash1Circuit<F> {
    pub a: Value<F>,
}

impl<F: FieldExt> Circuit<F> for Hash1Circuit<F> {
    type Config = Hash1Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let hash_selector = meta.selector();
        let instance = meta.instance_column();

        Hash1Chip::configure(meta, [col_a, col_b], hash_selector, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = Hash1Chip::construct(config);
        let b = chip.assign_advice_row(layouter.namespace(|| "load row"), self.a)?;
        chip.expose_public(layouter.namespace(|| "hash output check"), &b, 0)?;
        Ok(())
    }
}

mod tests {
    use super::Hash1Circuit;
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};
    #[test]
    fn test_hash_1() {
        let k = 4;
        let a = Value::known(Fp::from(2));
        let public_inputs = vec![Fp::from(4)];
        let circuit = Hash1Circuit { a };
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        let public_inputs = vec![Fp::from(8)];
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        assert!(prover.verify().is_err());
    }
}
