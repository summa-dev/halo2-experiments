use std::marker::PhantomData;
use gadgets::less_than::{LtChip, LtConfig, LtInstruction};
use eth_types::Field;

use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};

#[derive(Default)]
// define circuit struct using array of usernames and balances
struct MyCircuit<F> {
    pub value_l: u64,
    pub value_r: u64,
    pub check: bool,
    _marker: PhantomData<F>
}
#[derive(Clone, Debug)]
struct TestCircuitConfig<F> {
    q_enable: Selector,
    value_l: Column<Advice>,
    value_r: Column<Advice>,
    check: Column<Advice>,
    lt: LtConfig<F, 8>,
}

impl<F: Field> Circuit<F> for MyCircuit<F> {
    type Config = TestCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let q_enable = meta.complex_selector();
        let value_l = meta.advice_column();
        let value_r = meta.advice_column();
        let check = meta.advice_column();

        let lt = LtChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            |meta| meta.query_advice(value_l, Rotation::cur()),
            |meta| meta.query_advice(value_r, Rotation::cur()),
        );

        let config = Self::Config {
            q_enable,
            value_l,
            value_r,
            check,
            lt,
        };

        meta.create_gate("check is_lt between adjacent rows", |meta| {
            let q_enable = meta.query_selector(q_enable);

            // This verifies lt(value_l::cur, value_r::cur) is calculated correctly
            let check = meta.query_advice(config.check, Rotation::cur());

            vec![q_enable * (config.lt.is_lt(meta, None) - check)]
        });

        config
    }


    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {

        let chip = LtChip::construct(config.lt);

        layouter.assign_region(
            || "witness",
            |mut region| {
                region.assign_advice(
                    || "value left",
                    config.value_l,
                    0,
                    || Value::known(F::from(self.value_l)),
                )?;

                region.assign_advice(
                    || "value right",
                    config.value_r,
                    0,
                    || Value::known(F::from(self.value_r)),
                )?;

                region.assign_advice(
                    || "check",
                    config.check,
                    0,
                    || Value::known(F::from(self.check as u64)),
                )?;

                config.q_enable.enable(&mut region, 0)?;

                chip.assign(&mut region, 0, F::from(self.value_l), F::from(self.value_r))?;

                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {

    use super::MyCircuit;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr as Fp};
    use std::marker::PhantomData;

    #[test]
    fn test_less_than_2() {
        let k = 5;

        // initate usernames and balances array
        let value_l: u64 = 5;
        let value_r: u64 = 10;
        let check = true;

        let mut circuit = MyCircuit::<Fp> {
            value_l,
            value_r,
            check,
            _marker: PhantomData,
        };

        // Test 1 - should be valid
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();

        // switch value_l and value_r
        circuit.value_l = 10;
        circuit.value_r = 5;

        // Test 2 - should be invalid
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());


        // let check to be false
        circuit.check = false;

        // Test 3 - should be valid
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();

    }
}
