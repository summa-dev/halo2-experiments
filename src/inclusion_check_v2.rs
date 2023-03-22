use std::{marker::PhantomData};

use halo2_proofs::{
    arithmetic::Field,
    circuit::*,
    plonk::*,
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
            let cur_username_accumulator = meta.query_advice(username_accumulator_column, Rotation::cur());
            let prev_username_accumulator = meta.query_advice(username_accumulator_column, Rotation::prev());

            let balance = meta.query_advice(balance_column, Rotation::cur());
            let cur_balance_accumulator = meta.query_advice(balance_accumulator_column, Rotation::cur());
            let prev_balance_accumulator = meta.query_advice(balance_accumulator_column, Rotation::prev());

            vec![
                s.clone() * (username + cur_username_accumulator - prev_username_accumulator),
                s.clone() * (balance + cur_balance_accumulator - prev_balance_accumulator)
           ]
        });

        InclusionCheckV2Config { 
            advice: [username_column, balance_column, username_accumulator_column, balance_accumulator_column],
            selector,
            instance
        }
    }

    // Initiate the accumulator. This is the first row of the circuit
    pub fn init_accumulator(
        &self,
        mut layouter: impl Layouter<F>,
        zero_val: Value<F>
    ) -> Result<(AssignedCell<Assigned<F>, F>, AssignedCell<Assigned<F>, F>), Error> {
        
        layouter.assign_region(|| "table", |mut region| {

            // Assign a 0 value to username_accumulator_column at row 0
            let username_acc_cell = region.assign_advice(
                || "username accumulator init",
                self.config.advice[2], 
                0,
                || zero_val.into_field()
            )?;

            // Assign a 0 value to balance_accumulator_column at row 0 
            let balance_acc_cell = region.assign_advice(
                || "balance accumulator init",
                self.config.advice[3], 
                0,
                || zero_val.into_field()
            )?;

            Ok((username_acc_cell, balance_acc_cell))
        })
    }

    // Assign a generic row inside the instance column.
    // Selector for the custom gate is off
    pub fn assign_generic_row(
        &self,
        mut layouter: impl Layouter<F>,
        username: Value<F>,
        balance: Value<F>,
        last_user_accumulator_value: Value<Assigned<F>>,
        last_balance_accumulator_value: Value<Assigned<F>>,
    ) -> Result<(AssignedCell<Assigned<F>, F>, AssignedCell<Assigned<F>, F>), Error> {

        layouter.assign_region(|| "generic row", |mut region| {

            // Assign the value to username and balance to the cells inside the region
            region.assign_advice(
                || "username generic",
                self.config.advice[0], 
                0, 
                || username,
                )?;
            

            region.assign_advice(
            || "balance generic",
            self.config.advice[1], 
            0, 
            || balance,
            )?;

            // Assign a 0 value to username_accumulator_column at row 0
            let username_acc_cell = region.assign_advice(
                || "username accumulator generic",
                self.config.advice[2], 
                0,
                || last_user_accumulator_value
            )?;

            // Assign a 0 value to balance_accumulator_column at row 0 
            let balance_acc_cell = region.assign_advice(
                || "balance accumulator generic",
                self.config.advice[3], 
                0,
                || last_balance_accumulator_value
            )?;

            Ok((username_acc_cell, balance_acc_cell))

        })
    }

    pub fn assign_inclusion_check_row(
        &self,
        mut layouter: impl Layouter<F>,
        username: Value<F>,
        balance: Value<F>,
        last_user_accumulator_value: Value<Assigned<F>>,
        last_balance_accumulator_value: Value<Assigned<F>>,
    ) -> Result<(AssignedCell<Assigned<F>, F>, AssignedCell<Assigned<F>, F>), Error> { 

        layouter.assign_region(|| "inclusion row", |mut region| {

            self.config.selector.enable(&mut region, 0)?;

            // Assign the value to username and balance and return assigned cell
            region.assign_advice(
                || "username", // we are assigning to column a
                self.config.advice[0], 
                0, 
                || username,
             )?;
 
            region.assign_advice(
                || "balance",
                self.config.advice[1], 
                0, 
                || balance,
             )?;

            // Assign a 0 value to username_accumulator_column at row 0
            let username_acc_cell = region.assign_advice(
                || "username accumulator inclusion check row",
                self.config.advice[2], 
                0,
                || last_user_accumulator_value
            )?;

            // Assign a 0 value to balance_accumulator_column at row 0 
            let balance_acc_cell = region.assign_advice(
                || "balance accumulator inclusion check row",
                self.config.advice[3], 
                0,
                || last_balance_accumulator_value
            )?;

            Ok((username_acc_cell, balance_acc_cell))
        })
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        last_user_accumulator_cell: &AssignedCell<Assigned<F>, F>,
        last_balance_accumulator_cell: &AssignedCell<Assigned<F>, F>,
    )  -> Result<(), Error> {
        // enforce equality between public_username_cell and instance column at row 0
        layouter.constrain_instance(last_user_accumulator_cell.cell(), self.config.instance, 0)?;
        // enforce equality between balance_username_cell and instance column at row 1
        layouter.constrain_instance(last_balance_accumulator_cell.cell(), self.config.instance, 1)?;
        Ok(())
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

            // Initiate the accumulator
            let (mut prev_username_acc_cell, mut prev_balance_acc_cell) = chip.init_accumulator(layouter.namespace(|| "init accumulator"), self.zero_val)?;

            // loop over the usernames array and assign the rows
            for _i in 0..self.usernames.len() {
                // if row is equal to the inclusion index, assign the value using the assign_inclusion_check_row function
                // else assign the value using the assign_generic_row function
                if (_i as u8) == self.inclusion_index {
                    // extract username and balances cell from here!
                    let (user_accumulator_cell, balance_accumulator_cell)= chip.assign_inclusion_check_row(
                        layouter.namespace(|| "inclusion row"),
                        self.usernames[_i],
                        self.balances[_i],
                        prev_username_acc_cell.value_field(),
                        prev_balance_acc_cell.value_field()
                    )?;

                    // assign the accumulator
                    prev_username_acc_cell = user_accumulator_cell;
                    prev_balance_acc_cell = balance_accumulator_cell;
                } else {
                    let (user_accumulator_cell, balance_accumulator_cell) = chip.assign_generic_row(
                        layouter.namespace(|| "generic row"),
                        self.usernames[_i],
                        self.balances[_i],
                        prev_username_acc_cell.value_field(),
                        prev_balance_acc_cell.value_field()
                    )?;
                    // assign the accumulator
                    prev_username_acc_cell = user_accumulator_cell;
                    prev_balance_acc_cell = balance_accumulator_cell;
                }
            }

            // expose the public values
            chip.expose_public(layouter.namespace(|| "expose public"), &prev_username_acc_cell, &prev_balance_acc_cell)?;

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

        // // Test 2 - Inclusion check on a existing entry but not for the corresponding inclusion_index
        // let public_input_invalid = vec![Fp::from(8), Fp::from(16)];
        // let prover = MockProver::run(k, &circuit, vec![public_input_invalid]).unwrap();
        // assert!(prover.verify().is_err());

        // // Test 3 - Inclusion check on a non-existing entry
        // let public_input_invalid2 = vec![Fp::from(10), Fp::from(20)];
        // let prover = MockProver::run(k, &circuit, vec![public_input_invalid2]).unwrap();
        // assert!(prover.verify().is_err());

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



// To test: 

// - Check what happen if I disable the enabled equality on the instance column
// - Consistency with names