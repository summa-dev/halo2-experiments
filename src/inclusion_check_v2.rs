// use std::{marker::PhantomData};

// use halo2_proofs::{
//     arithmetic::Field,
//     circuit::*,
//     plonk::*,
// };

// use halo2curves::{
//     pasta::*
// };


// #[derive(Debug, Clone)]
// struct InclusionCheckV2Config {
//     pub advice: [Column<Advice>; 4],
//     pub selector: Selector,
//     pub instance: Column<Instance>,
// }

// struct InclusionCheckV2Chip<F: Field> {
//     config: InclusionCheckV2Config,
//     _marker: PhantomData<F>,
// }

// impl<F: Field> InclusionCheckV2Chip<F> {

//     pub fn construct(config: InclusionCheckV2Config) -> Self {
//         Self {
//             config,
//             _marker: PhantomData
//         }
//     }

//     pub fn configure(
//         meta: &mut ConstraintSystem<F>,
//         advice: [Column<Advice>; 4],
//         selector: Selector,
//         instance: Column<Instance>,
//     ) -> InclusionCheckV2Config {

//         let username_column = advice[0];
//         let balance_column = advice[1];
//         let username_accumulator_column = advice[2];
//         let balance_accumulator_column = advice[3];

//         // Enable equality on the username_accumulator_column and balance_accumulator_column to enable permutation check
//         meta.enable_equality(username_accumulator_column);
//         meta.enable_equality(balance_accumulator_column);

//         // Enable equality on the instance column to enable permutation check
//         meta.enable_equality(instance);

//         InclusionCheckV2Config { 
//             advice: [username_column, balance_column, username_accumulator_column, balance_accumulator_column],
//             selector,
//             instance
//         }
//     }

//     // Initiate the accumulator. This is the first row of the circuit
//     pub fn init_accumulator(
//         &self,
//         mut layouter: impl Layouter<F>,
//     ) -> Result<(), Error> {

//         layouter.assign_region(|| "init accumulator", |mut region| {

//             // Assign a 0 value to username_accumulator_column
//             region.assign_advice(
//                 || "username accumulator init",
//                 self.config.advice[2], 
//                 0, 
//                 || Value::known(Fp::from(2))
//                 )?;

//             // Assign a 0 value to balance_accumulator_column
//             region.assign_advice(
//                 || "balance accumulator init",
//                 self.config.advice[3], 
//                 0, 
//                 || 0
//                 )?;

//             Ok(())
//         })
//     }

//     // Assign the row inside the instance column. 
//     pub fn assign_row(
//         &self,
//         mut layouter: impl Layouter<F>,
//         username: Value<Assigned<F>>,
//         balance: Value<Assigned<F>>,
//     ) -> Result<(), Error> {

//         layouter.assign_region(|| "generic row", |mut region| {

//             // Assign the value to username and balance to the cells inside the region
//             region.assign_advice(
//                 || "username",
//                 self.config.advice[0], 
//                 0, 
//                 || username,
//                 )?;

//             region.assign_advice(
//             || "balance",
//             self.config.advice[1], 
//             0, 
//             || balance,
//             )?;

//                 Ok(())
//         })
        
//     }

//     pub fn assign_inclusion_check_row() {

//     }

//     pub fn expose_public() {

//     }

// }
    


// // To test: 

// // - Check what happen if I disable the enabled equality on the instance column