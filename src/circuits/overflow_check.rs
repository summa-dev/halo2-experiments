use super::super::chips::overflow_check::{OverFlowCheckConfig, OverFlowChip};

use halo2_proofs::{circuit::*, halo2curves::pasta::Fp, plonk::*};

#[derive(Default)]
struct OverflowCheckCircuit {
    pub a: Value<Fp>,
}

impl Circuit<Fp> for OverflowCheckCircuit {
    type Config = OverFlowCheckConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let col_a = meta.advice_column();
        let col_b_inv = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let col_d = meta.advice_column();
        let carry_selector = meta.selector();
        let overflow_selector = meta.selector();
        let instance = meta.instance_column();

        OverFlowChip::configure(
            meta,
            [col_a, col_b_inv, col_b, col_c, col_d],
            [carry_selector, overflow_selector],
            instance,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = OverFlowChip::construct(config);

        let (prev_b, prev_c, prev_d) =
            chip.assign_first_row(layouter.namespace(|| "load first row"))?;

        let (b, c, d) = chip.assign_advice_row(
            layouter.namespace(|| "load row"),
            self.a,
            prev_b.clone(),
            prev_c.clone(),
            prev_d.clone(),
        )?;

        // check computation result
        chip.expose_public(layouter.namespace(|| "overflow check"), &b, 2)?;
        chip.expose_public(layouter.namespace(|| "sum_high check"), &c, 3)?;
        chip.expose_public(layouter.namespace(|| "sum_low check"), &d, 4)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::panic;
    use super::OverflowCheckCircuit;
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};
    #[test]
    fn test_none_overflow_case() {
        let k = 4;

        // a: new value
        let a = Value::known(Fp::from((1 << 16) + 3));
        let public_inputs = vec![
            // initial values for A[3], A[4], last two columns
            Fp::from(0),
            Fp::from((1 << 16) - 2),
            //
            // checking value
            Fp::from(0), // 2^32 <- 0 means not overflowed
            Fp::from(2), // 2^16
            Fp::from(1), // 2^0
        ];

        let circuit = OverflowCheckCircuit { a };
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        prover.assert_satisfied();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_overflow_case() {
        let k = 4;

        // a: new value
        let a = Value::known(Fp::from((1 << 32) + 2));
        let public_inputs = vec![
            // initial values for A[3], A[4], last two columns
            Fp::from(0),             // 0 * 2^16
            Fp::from((1 << 16) - 1), // only for testing, over 2^16 is not allowed on accumulated columns
            //
            // checking value
            Fp::from(1), // 2^32 <- not 0 means overflowed
            Fp::from(1), // 2^16
            Fp::from(1), // 2^0
        ];

        let circuit = OverflowCheckCircuit { a };
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();

        // TODO: should check panic message
        let panic_result = panic::catch_unwind(|| prover.assert_satisfied());
        assert!(panic_result.is_err());
    }
}
