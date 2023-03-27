use super::super::chips::inclusion_check_v2::{InclusionCheckV2Chip, InclusionCheckV2Config};

use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*};

#[derive(Default)]
// define circuit struct using array of usernames and balances
struct MyCircuit<F> {
    pub usernames: [Value<F>; 10],
    pub balances: [Value<F>; 10],
    pub inclusion_index: u8,
    pub zero_val: Value<F>,
}

impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
    type Config = InclusionCheckV2Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let col_username = meta.advice_column();
        let col_balance = meta.advice_column();
        let col_username_accumulator = meta.advice_column();
        let col_balance_accumulator = meta.advice_column();
        let selector = meta.selector();
        let instance = meta.instance_column();

        InclusionCheckV2Chip::configure(
            meta,
            [
                col_username,
                col_balance,
                col_username_accumulator,
                col_balance_accumulator,
            ],
            selector,
            instance,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // We create a new instance of chip using the config passed as input
        let chip = InclusionCheckV2Chip::<F>::construct(config);

        let (user_acc_last_row_cell, balance_acc_last_row_cell) = chip.assign_rows(
            layouter.namespace(|| "init table"),
            self.usernames,
            self.balances,
            self.zero_val,
            self.inclusion_index,
        )?;

        chip.expose_public(
            layouter.namespace(|| "expose public"),
            &user_acc_last_row_cell,
            0,
        )?;
        chip.expose_public(
            layouter.namespace(|| "expose public"),
            &balance_acc_last_row_cell,
            1,
        )?;

        Ok(())
    }
}

mod tests {

    use super::MyCircuit;
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};

    #[test]
    fn test_inclusion_check_2() {
        let k = 5;

        // initate usernames and balances array
        let mut usernames: [Value<Fp>; 10] = [Value::default(); 10];
        let mut balances: [Value<Fp>; 10] = [Value::default(); 10];

        // add 10 values to the username array and balances array
        for i in 0..10 {
            usernames[i] = Value::known(Fp::from(i as u64));
            balances[i] = Value::known(Fp::from(i as u64) * Fp::from(2));
        }

        // Table is
        // username | balance
        // 0        | 0
        // 1        | 2
        // 2        | 4
        // 3        | 6
        // 4        | 8
        // 5        | 10
        // 6        | 12
        // 7        | 14
        // 8        | 16
        // 9        | 18

        let circuit = MyCircuit::<Fp> {
            usernames,
            balances,
            inclusion_index: 7,
            zero_val: Value::known(Fp::zero()),
        };

        // Test 1 - Inclusion check on a existing entry for the corresponding inclusion_index
        let public_input_valid = vec![Fp::from(7), Fp::from(14)];
        let prover = MockProver::run(k, &circuit, vec![public_input_valid]).unwrap();
        prover.assert_satisfied();

        // Test 2 - Inclusion check on a existing entry but not for the corresponding inclusion_index
        let public_input_invalid = vec![Fp::from(8), Fp::from(16)];
        let prover = MockProver::run(k, &circuit, vec![public_input_invalid]).unwrap();
        assert!(prover.verify().is_err());

        // Test 3 - Inclusion check on a non-existing entry
        let public_input_invalid2 = vec![Fp::from(10), Fp::from(20)];
        let prover = MockProver::run(k, &circuit, vec![public_input_invalid2]).unwrap();
        assert!(prover.verify().is_err());
    }
}
