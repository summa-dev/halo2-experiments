use std::{marker::PhantomData, usize};

use halo2_proofs::{
    arithmetic::Field,
    circuit::*,
    plonk::*,
};

// #[derive(Debug, Clone)]
// struct ACell<F: Field>(AssignedCell<F, F>);

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
        username: Option<F>,
        balance: Option<F>
    ) -> Result<(), Error> {
        Ok(())
    }

    pub fn assign_inclusion_check_row(
        &self,
        mut layouter: impl Layouter<F>,
        username: Option<F>,
        balance: Option<F>
    ) -> Result<(), Error> {

        Ok(())
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        public_username_cell: &AssignedCell<F, F>,
        public_balance_cell: &AssignedCell<F, F>,
        row: usize
    ) -> Result<(), Error> {
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
    struct MyCircuit<F: Field> {
        pub usernames: [Option<F>; 10],
        pub balances: [Option<F>; 10],
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
                    let result = chip.assign_inclusion_check_row(
                        layouter.namespace(|| "inclusion check row"),
                        self.usernames[_i],
                        self.balances[_i]);
                } else {
                    let result = chip.assign_generic_row(
                        layouter.namespace(|| "general row"),
                        self.usernames[_i],
                        self.balances[_i]);                
                }
            }

            // expose public function

            Ok(())
        }

    }

    #[test]
    // fn test_range_check_1() {
    //     let k = 4;
    //     const RANGE: usize = 8; // 3-bit value

    //     // Successful cases i=0,1,2,3,4,5,6,7
    //     for i in 0..RANGE {
    //         let circuit = MyCircuit::<Fp, RANGE> {
    //             value: Value::known(Fp::from(i as u64).into()),
    //         };

    //         let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    //         prover.assert_satisfied();
    //     }

    //     // Out-of-range `value = 8`
    //     {
    //         let circuit = MyCircuit::<Fp, RANGE> {
    //             value: Value::known(Fp::from(RANGE as u64).into()),
    //         };
    //         let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    //         // prover.assert_satisfied(); // this should fail!
    //         assert_eq!(
    //             prover.verify(),
    //             Err(vec![VerifyFailure::ConstraintNotSatisfied {
    //                 constraint: ((0, "range check").into(), 0, "range check").into(),
    //                 location: FailureLocation::InRegion {
    //                     region: (0, "Assign value").into(),
    //                     offset: 0
    //                 },
    //                 cell_values: vec![(((Any::Advice, 0).into(), 0).into(), "0x8".to_string())]
    //             }])
    //         );
    //     }
    // }

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