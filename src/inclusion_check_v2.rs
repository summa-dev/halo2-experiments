use std::{marker::PhantomData};

use halo2_proofs::{
    arithmetic::Field,
    circuit::*,
    plonk::{Advice, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};

use halo2curves::{
    pasta::*
};


#[derive(Debug, Clone)]
struct InclusionCheckV2Config {
    pub advice: [Column<Advice>; 4],
    pub selector: Selector,
    pub instance: Column<Instance>,
}

struct InclusionCheckV2Chip<F: Field> {
    config: InclusionCheckV2Config,
    _marker: PhantomData<F>,
}

impl<F: Field> InclusionCheckV2Chip<F> {

    pub fn construct(config: InclusionCheckV2Config) -> Self {
        Self {
            config,
            _marker: PhantomData
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 4],
        selector: Selector,
        instance: Column<Instance>,
    ) -> InclusionCheckV2Config {

        let username_column = advice[0];
        let balance_column = advice[1];
        let username_accumulator_column = advice[2];
        let balance_accumulator_column = advice[3];

        // Enable equality on the username_accumulator_column and balance_accumulator_column to enable permutation check
        meta.enable_equality(username_accumulator_column);
        meta.enable_equality(balance_accumulator_column);

        // Enable equality on the instance column to enable permutation check
        meta.enable_equality(instance);

        meta.create_gate("accumulator constraint", |meta| {

            let s = meta.query_selector(selector);
            let username = meta.query_advice(username_column, Rotation::cur());
            let username_accumulator = meta.query_advice(username_accumulator_column, Rotation::cur());
            let prev_username_accumulator = meta.query_advice(username_accumulator_column, Rotation::prev());

            let balance = meta.query_advice(balance_column, Rotation::cur());
            let balance_accumulator = meta.query_advice(balance_accumulator_column, Rotation::cur());
            let prev_balance_accumulator = meta.query_advice(balance_accumulator_column, Rotation::prev());

            vec![
                s.clone() * (username + prev_username_accumulator - username_accumulator),
                s.clone() * (balance + prev_balance_accumulator - balance_accumulator)
           ]
        });

        InclusionCheckV2Config { 
            advice: [username_column, balance_column, username_accumulator_column, balance_accumulator_column],
            selector,
            instance
        }
    }

    // Assign rows for instance column passing the entry of the users
    pub fn assign_rows(
        &self,
        mut layouter: impl Layouter<F>,
        usernames: [Value<F>; 10],
        balances: [Value<F>; 10],
        zero_val: Value<F>,
        inclusion_index: u8,
    ) -> Result<(AssignedCell<F, F>,AssignedCell<F, F>), Error> {

        layouter.assign_region(|| "user and balance table", |mut region| {

            // for the first row, assign the zero value to the accumulator
            let mut user_acc_cell = region.assign_advice(
                || "username accumulator init",
                self.config.advice[2], 
                0,
                || zero_val
            )?;

            let mut balance_acc_cell = region.assign_advice(
                || "balance accumulator init",
                self.config.advice[3], 
                0,
                || zero_val
            )?;

            let mut username_acc_value = zero_val;
            let mut balance_acc_value = zero_val;

            // loop over the username and balance arrays and assign the values to the table
            for _i in 0..usernames.len() {

                if (_i as u8) == inclusion_index {

                    self.config.selector.enable(&mut region, _i + 1)?;

                    region.assign_advice(
                        || "username",
                        self.config.advice[0], 
                        _i + 1,
                        || usernames[_i]
                    )?;

                    region.assign_advice(
                        || "balance",
                        self.config.advice[1], 
                        _i + 1,
                        || balances[_i]
                    )?;

                    user_acc_cell = region.assign_advice(
                        || "username accumulator",
                        self.config.advice[2], 
                        _i + 1,
                        || usernames[_i]
                    )?;

                    balance_acc_cell = region.assign_advice(
                        || "balance accumulator",
                        self.config.advice[3], 
                        _i + 1,
                        || balances[_i]
                    )?;

                    
                    username_acc_value = usernames[_i];
                    balance_acc_value = balances[_i];
                }

                else {

                    region.assign_advice(
                        || "username",
                        self.config.advice[0], 
                        _i + 1,
                        || usernames[_i]
                    )?;

                    region.assign_advice(
                        || "balance",
                        self.config.advice[1], 
                        _i + 1,
                        || balances[_i]
                    )?;

                    user_acc_cell = region.assign_advice(
                        || "username accumulator",
                        self.config.advice[2], 
                        _i + 1,
                        || username_acc_value
                    )?;

                    balance_acc_cell = region.assign_advice(
                        || "balance accumulator",
                        self.config.advice[3], 
                        _i + 1,
                        || balance_acc_value
                    )?;

                }
            }
            Ok((user_acc_cell, balance_acc_cell))
    })
}


pub fn expose_public(&self, mut layouter: impl Layouter<F>, cell: &AssignedCell<F, F>, row: usize) -> Result<(), Error> {
    layouter.constrain_instance(cell.cell(), self.config.instance, row)
}

}

mod tests {
    use halo2_proofs::{
        // circuit::floor_planner::V1,
        dev::{FailureLocation, MockProver, VerifyFailure},
        // plonk::{Any, Circuit},
        plonk::{Any, Circuit},
    };

    use halo2curves::{
        pasta::*
    };

    use super::*;

    #[derive(Default)] 

    // define circuit struct using array of usernames and balances 
    struct MyCircuit<F> {
        pub usernames: [Value<F>; 10],
        pub balances: [Value<F>; 10],
        pub inclusion_index: u8,
        pub zero_val: Value<F>,
    }

    impl<F: Field> Circuit<F> for MyCircuit<F> {
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

            InclusionCheckV2Chip::configure(meta, [col_username, col_balance, col_username_accumulator, col_balance_accumulator], selector, instance)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>
        ) -> Result<(), Error> {
            // We create a new instance of chip using the config passed as input
            let chip = InclusionCheckV2Chip::<F>::construct(config);

            // println!("accumulator init");
            // // Initiate the accumulator
            // chip.init_accumulator(layouter.namespace(|| "init accumulator"), self.zero_val)?;

            let (user_acc_last_row_cell, balance_acc_last_row_cell) = chip.assign_rows(
            layouter.namespace(|| "init table"),
            self.usernames,
            self.balances,
            self.zero_val,
            self.inclusion_index
            )?;

            chip.expose_public(layouter.namespace(|| "expose public"), &user_acc_last_row_cell, 0)?;
            chip.expose_public(layouter.namespace(|| "expose public"), &balance_acc_last_row_cell, 1)?;

            Ok(())
        }

    }

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

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_inclusion_check_2() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("inclusion-check-1-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Inclusion Check 1 Layout", ("sans-serif", 60))
            .unwrap();

        let mut usernames: [Value<Assigned<Fp>>; 10] = [Value::default(); 10];
        let mut balances: [Value<Assigned<Fp>>; 10] = [Value::default(); 10];
    
        let circuit = MyCircuit::<Fp> {
            usernames, 
            balances,
            inclusion_index: 2
        };

        halo2_proofs::dev::CircuitLayout::default()
            .render(3, &circuit, &root)
            .unwrap();
    }