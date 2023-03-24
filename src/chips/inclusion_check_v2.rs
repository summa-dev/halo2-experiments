use std::{marker::PhantomData};

use halo2_proofs::{
    arithmetic::Field,
    circuit::*,
    plonk::{Advice, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};

#[derive(Debug, Clone)]
pub struct InclusionCheckV2Config {
    pub advice: [Column<Advice>; 4],
    pub selector: Selector,
    pub instance: Column<Instance>,
}

pub struct InclusionCheckV2Chip<F: Field> {
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