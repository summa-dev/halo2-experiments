use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::*,
    plonk::{Advice, Column, Fixed, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};

#[derive(Debug, Clone)]
pub struct InclusionCheckV2Config {
    pub advice: [Column<Advice>; 4],
    pub selector: Selector,
    pub instance: Column<Instance>,
    pub constant: Column<Fixed>,
}
#[derive(Debug, Clone)]
pub struct InclusionCheckV2Chip<F: FieldExt> {
    config: InclusionCheckV2Config,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> InclusionCheckV2Chip<F> {
    pub fn construct(config: InclusionCheckV2Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 4],
        instance: Column<Instance>,
        constant: Column<Fixed>,
    ) -> InclusionCheckV2Config {
        let username_column = advice[0];
        let balance_column = advice[1];
        let username_accumulator_column = advice[2];
        let balance_accumulator_column = advice[3];

        // create check selector
        let selector = meta.selector();

        // Enable equality on the username_accumulator_column and balance_accumulator_column to enable permutation check
        meta.enable_equality(username_accumulator_column);
        meta.enable_equality(balance_accumulator_column);

        // Enable constant column. Api to enable constant column to be used for assignement
        meta.enable_constant(constant);

        // Enable equality on the instance column to enable permutation check
        meta.enable_equality(instance);

        meta.create_gate("accumulator constraint", |meta| {
            let s = meta.query_selector(selector);
            let username = meta.query_advice(username_column, Rotation::cur());
            let username_accumulator =
                meta.query_advice(username_accumulator_column, Rotation::cur());
            let prev_username_accumulator =
                meta.query_advice(username_accumulator_column, Rotation::prev());

            let balance = meta.query_advice(balance_column, Rotation::cur());
            let balance_accumulator =
                meta.query_advice(balance_accumulator_column, Rotation::cur());
            let prev_balance_accumulator =
                meta.query_advice(balance_accumulator_column, Rotation::prev());

            vec![
                s.clone() * (username + prev_username_accumulator - username_accumulator),
                s * (balance + prev_balance_accumulator - balance_accumulator),
            ]
        });

        InclusionCheckV2Config {
            advice: [
                username_column,
                balance_column,
                username_accumulator_column,
                balance_accumulator_column,
            ],
            selector,
            instance,
            constant
        }
    }

    // Assign rows for instance column passing the entry of the users
    pub fn assign_rows(
        &self,
        mut layouter: impl Layouter<F>,
        usernames: [Value<F>; 10],
        balances: [Value<F>; 10],
        constant: F,
        inclusion_index: u8,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {

        // For row 0, assign the zero value from constant to the accumulator
        layouter.assign_region(
            || "user and balance table",
            |mut region| {

                // for the first row, assign the zero value to the accumulator
                let mut username_acc_cell = region.assign_advice_from_constant(
                    || "username accumulator init",
                    self.config.advice[2],
                    0,
                    constant,
                )?;

                let mut balance_acc_cell = region.assign_advice_from_constant(
                    || "balance accumulator init",
                    self.config.advice[3],
                    0,
                    constant,
                )?;

                // for the other rows loop over the username and balance arrays and assign the values to the table
                // if the row is the inclusion index, enable the selector and assign the value to the accumulator
                // if the row is not the inclusion index, copy the accumulator from the previous row
                for _i in 0..usernames.len() {
                    if (_i as u8) == inclusion_index {
                        self.config.selector.enable(&mut region, _i + 1)?;

                        region.assign_advice(
                            || "username",
                            self.config.advice[0],
                            _i + 1,
                            || usernames[_i],
                        )?;

                        region.assign_advice(
                            || "balance",
                            self.config.advice[1],
                            _i + 1,
                            || balances[_i],
                        )?;

                        username_acc_cell = region.assign_advice(
                            || "username accumulator",
                            self.config.advice[2],
                            _i + 1,
                            || usernames[_i],
                        )?;

                        balance_acc_cell = region.assign_advice(
                            || "balance accumulator",
                            self.config.advice[3],
                            _i + 1,
                            || balances[_i],
                        )?;

                    } else {
                        region.assign_advice(
                            || "username",
                            self.config.advice[0],
                            _i + 1,
                            || usernames[_i],
                        )?;

                        region.assign_advice(
                            || "balance",
                            self.config.advice[1],
                            _i + 1,
                            || balances[_i],
                        )?;

                        username_acc_cell = username_acc_cell.copy_advice(
                            || "copy username acc cell from prev row",
                            &mut region,
                            self.config.advice[2], 
                            _i + 1
                        )?;

                        balance_acc_cell = balance_acc_cell.copy_advice(
                            || "copy balance acc cell from prev row",
                            &mut region,
                            self.config.advice[3], 
                            _i + 1
                        )?;

                    }
                }
                Ok((username_acc_cell, balance_acc_cell))
            },
        )
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        cell: &AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}
