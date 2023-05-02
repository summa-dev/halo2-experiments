use super::super::chips::safe_accumulator::{SafeAccumulatorConfig, SafeACcumulatorChip};
use halo2_proofs::{circuit::*, halo2curves::pasta::Fp, plonk::*};

#[derive(Default)]
struct SafeAccumulatorCircuit {
    pub values: Vec<Value<Fp>>,
    pub accumulated_value: [Value<Fp>; 4],
}

impl Circuit<Fp> for SafeAccumulatorCircuit {
    type Config = SafeAccumulatorConfig<4, 4>; // 4 bits for each column and 4 columns
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let new_value = meta.advice_column();
        let left_most_acc_inv = meta.advice_column();
        let carry_cols = [meta.advice_column(), meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let acc_cols = [meta.advice_column(), meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let add_selector = meta.selector();
        let overflow_selector = meta.selector();
        let instance = meta.instance_column();

        SafeACcumulatorChip::<4, 4>::configure(
            meta,
            new_value,
            left_most_acc_inv,
            carry_cols,
            acc_cols,
            [add_selector, overflow_selector],
            instance,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = SafeACcumulatorChip::construct(config);

        let (mut assigned_cells, mut previous_accumulates) = chip.assign(
            layouter.namespace(|| "initial rows"),
            0,
            self.values[0],
            self.accumulated_value,
        ).unwrap();

        // Actually, there is no need to multiple values for a single user.
        // It may need multiple values who has multiple accounts in same identity
        // so, I just keep this code for now.
        let mut latest_accumulates: [Value<Fp>; 4];
        for (i, v) in self.values.iter().skip(1).enumerate() {
            (assigned_cells, latest_accumulates) = chip.assign(
                layouter.namespace(|| "additional rows"),
                i,
                *v,
                previous_accumulates,
            ).unwrap();
            previous_accumulates = latest_accumulates;
        }

        // check assigned cells values are correct with instance
        for (i, cell) in assigned_cells.iter().rev().enumerate() {
            chip.expose_public(layouter.namespace(|| format!("accumulate_{}", i)), cell, i);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SafeAccumulatorCircuit;
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::{pasta::Fp, FieldExt}};

    #[test]
    fn test_none_overflow_case() {
        let k = 8;

        let values = vec![Value::known(Fp::from(4))];
        let accumulated_value = [
            Value::known(Fp::from(0)),
            Value::known(Fp::from(0)),
            Value::known(Fp::from((1 << 4) - 2)), // 0xe
            Value::known(Fp::from((1 << 4) - 3)), // 0xd
        ];

        let result_accumulated = vec![
            Fp::from(0),
            Fp::from(0),
            Fp::from((1 << 4) - 1), // 0xf
            Fp::from(1),            // 0x1
        ];

        let circuit = SafeAccumulatorCircuit {
            values,
            accumulated_value,
        };
        let prover = MockProver::run(k, &circuit, vec![result_accumulated]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_none_overflow_case_with_multiple_values() {
        let k = 8;

        let values = vec![Value::known(Fp::from(1)), Value::known(Fp::from(3))];
        let accumulated_value = [
            Value::known(Fp::from(0)),
            Value::known(Fp::from(0)),
            Value::known(Fp::from((1 << 4) - 2)), // 0xe
            Value::known(Fp::from((1 << 4) - 3)), // 0xd
        ];

        let result_accumulated = vec![
            Fp::from(0),
            Fp::from(0),
            Fp::from((1 << 4) - 1), // 0xf
            Fp::from(1),            // 0x1
        ];

        let circuit = SafeAccumulatorCircuit {
            values,
            accumulated_value,
        };
        let prover = MockProver::run(k, &circuit, vec![result_accumulated]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_overflow_case() {
        let k = 8;

        let values = vec![Value::known(Fp::from(4))];
        let accumulated_value = [
            Value::known(Fp::from(0)),
            Value::known(Fp::from((1 << 4) - 1)), // 0xf
            Value::known(Fp::from((1 << 4) - 1)), // 0xf
            Value::known(Fp::from((1 << 4) - 3)), // 0xd
        ];

        let circuit = SafeAccumulatorCircuit {
            values,
            accumulated_value,
        };
        let invalid_prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
        assert!(invalid_prover.verify().is_err());
    }
}
