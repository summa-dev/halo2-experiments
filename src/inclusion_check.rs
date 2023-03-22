use std::{marker::PhantomData};

use halo2_proofs::{
    arithmetic::Field,
    circuit::*,
    plonk::*,
};

#[derive(Debug, Clone)]
struct InclusionCheckConfig { 
    pub advice: [ Column<Advice>; 2],
    pub selector: Selector,
    pub instance: Column<Instance>,
}

struct InclusionCheckChip<F: Field>  {
    config: InclusionCheckConfig,
    _marker: PhantomData<F>,
}

impl<F: Field> InclusionCheckChip<F> {

    pub fn construct(config: InclusionCheckConfig) -> Self {
        Self {
            config,
            _marker: PhantomData
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
        instance: Column<Instance>,
    ) -> InclusionCheckConfig {
        
        // decompose array to fetch 2 advice column
        let col_username = advice[0];
        let col_balance = advice[1];
        // create the selector
        let selector = meta.selector();

        // enable equality for permutation check on the advice columns
        meta.enable_equality(col_username);
        meta.enable_equality(col_balance);
        // we also enable equality on the instance column as we need to execute permutation check on that
        meta.enable_equality(instance);

        InclusionCheckConfig{
            advice: [col_username, col_balance],
            selector,
            instance
        }
    }

    pub fn assign_generic_row(
        &self,
        mut layouter: impl Layouter<F>,
        username: Value<Assigned<F>>,
        balance: Value<Assigned<F>>
    ) -> Result<(), Error> {
        layouter.assign_region(|| "first row", |mut region| {

            // no need to turn on the selector gate for the generic row

            // Assign the value to username and balance 
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

             Ok(())
        })

   }

    pub fn assign_inclusion_check_row(
        &self,
        mut layouter: impl Layouter<F>,
        username: Value<Assigned<F>>,
        balance: Value<Assigned<F>>
    ) -> Result<(AssignedCell<Assigned<F>, F>, AssignedCell<Assigned<F>, F>), Error> { 

        layouter.assign_region(|| "first row", |mut region| {

            // We need to enable the selector in this region
            self.config.selector.enable(&mut region, 0)?;

            // Assign the value to username and balance and return assigned cell
            let username_cell = region.assign_advice(
                || "username", // we are assigning to column a
                self.config.advice[0], 
                0, 
                || username,
             )?;

             let balance_cell = region.assign_advice(
                || "balance",
                self.config.advice[1], 
                0, 
                || balance,
             )?;

            Ok((username_cell, balance_cell))
        })

    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        public_username_cell: &AssignedCell<Assigned<F>, F>,
        public_balance_cell: &AssignedCell<Assigned<F>, F>,
    )  -> Result<(), Error> {
        // enforce equality between public_username_cell and instance column at row 0
        layouter.constrain_instance(public_username_cell.cell(), self.config.instance, 0)?;
        // enforce equality between balance_username_cell and instance column at row 1
        layouter.constrain_instance(public_balance_cell.cell(), self.config.instance, 1)?;

        Ok(())
    }
}

mod tests {
    use halo2_proofs::{
        circuit::floor_planner::V1,
        dev::{FailureLocation, MockProver, VerifyFailure},
        plonk::{Any, Circuit},
    };

    use halo2curves::{
        pasta::*
    };

    use super::*;

    #[derive(Default)] 

    // define circuit struct using array of usernames and balances 
    struct MyCircuit<F> {
        pub usernames: [Value<Assigned<F>>; 10],
        pub balances: [Value<Assigned<F>>; 10],
        pub inclusion_index: u8
    }

    impl<F: Field> Circuit<F> for MyCircuit<F> {
        type Config = InclusionCheckConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let col_username = meta.advice_column();
            let col_balance = meta.advice_column();
            let instance = meta.instance_column();

            InclusionCheckChip::configure(meta, [col_username, col_balance], instance)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>
        ) -> Result<(), Error> {
            // We create a new instance of chip using the config passed as input
            let chip = InclusionCheckChip::<F>::construct(config);

            // loop over the usernames array and assign the rows
            for _i in 0..self.usernames.len() {
                // if row is equal to the inclusion index, assign the value using the assign_inclusion_check_row function
                // else assign the value using the assign_generic_row function
                if (_i as u8) == self.inclusion_index {
                    // extract username and balances cell from here!
                    let (username_cell, balance_cell) = chip.assign_inclusion_check_row(
                        layouter.namespace(|| "inclusion row"),
                        self.usernames[_i],
                        self.balances[_i])?;
                    
                    // expose the public values
                    chip.expose_public(layouter.namespace(|| "expose public"), &username_cell, &balance_cell)?;
                } else {
                    chip.assign_generic_row(
                        layouter.namespace(|| "generic row"),
                        self.usernames[_i],
                        self.balances[_i])?;                
                }
            }
            Ok(())
        }

    }

    #[test]
    fn test_inclusion_check() {
        let k = 4;

        // initiate a circuit with 10 usernames and balances
        let circuit = MyCircuit::<Fp> {
            usernames: [Value::known(Fp::from(1_u64).into()); 10],
            balances: [Value::known(Fp::from(1_u64).into()); 10],
            inclusion_index: 0
        };

        let public_input = vec![Fp::from(1), Fp::from(1)];

        let prover = MockProver::run(k, &circuit, vec![public_input]).unwrap();
        prover.assert_satisfied();

    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_range_check_1() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("range-check-1-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Range Check 1 Layout", ("sans-serif", 60))
            .unwrap();

        let circuit = MyCircuit::<Fp, 8> {
            value: Value::unknown(),
        };
        halo2_proofs::dev::CircuitLayout::default()
            .render(3, &circuit, &root)
            .unwrap();
    }
}

// Questions: 

// - should the selector be initiated inside the configure function or outside?
// - does it make sense to define the circuit like this struct MyCircuit<F>?
// - need to assert that lenght of usernames and balance vector is the same
// - parametrize the length of the array
// - do we need to use the result returned from the assignement?
// - do I need struct ACell?
// - what is the role of the selector in here?
// - Write better tests
// - Test case where the queried username and balance are in 2 different rows