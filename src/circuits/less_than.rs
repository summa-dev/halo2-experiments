use super::super::chips::less_than::{LessThanChip, LessThanConfig};

use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*};

#[derive(Default)]

// define circuit struct using array of usernames and balances
struct MyCircuit<F> {
    pub input: Value<F>,
}

impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
    type Config = LessThanConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let input = meta.advice_column();
        let table = meta.instance_column();

        LessThanChip::configure(meta, input, table)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // We create a new instance of chip using the config passed as input
        let chip = LessThanChip::<F>::construct(config);

        // assign value to the chip
        let _ = chip.assign(layouter.namespace(|| "init table"), self.input);

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::MyCircuit;
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};
    #[test]
    fn test_less_than_2() {
        let k = 10;

        // initate value
        let value = Value::known(Fp::from(755));

        let circuit = MyCircuit::<Fp> {
            input: value
        };

        let target = 800;

        // define public inputs looping from target to 0 and adding each value to pub_inputs vector
        let mut pub_inputs = vec![];
        for i in 0..target {
            pub_inputs.push(Fp::from(i));
        }

        // should verify as value is less than target
        let prover = MockProver::run(k, &circuit, vec![pub_inputs]).unwrap();
        prover.assert_satisfied();

        // shouldn't verify as value is greater than target
        let target_2 = 754;

        let mut pub_inputs_2 = vec![];
        for i in 0..target_2 {
            pub_inputs_2.push(Fp::from(i));
        }

        let invalid_prover = MockProver::run(k, &circuit, vec![pub_inputs_2]).unwrap();

        assert!(invalid_prover.verify().is_err());

    }
}
