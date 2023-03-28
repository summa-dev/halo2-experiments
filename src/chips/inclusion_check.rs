use std::marker::PhantomData;

use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*};

#[derive(Debug, Clone)]
pub struct InclusionCheckConfig {
    pub advice: [Column<Advice>; 2],
    pub instance: Column<Instance>,
}
#[derive(Debug, Clone)]
pub struct InclusionCheckChip<F: FieldExt> {
    config: InclusionCheckConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> InclusionCheckChip<F> {
    pub fn construct(config: InclusionCheckConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
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

        // enable equality for permutation check on the advice columns
        meta.enable_equality(col_username);
        meta.enable_equality(col_balance);
        // we also enable equality on the instance column as we need to execute permutation check on that
        meta.enable_equality(instance);

        InclusionCheckConfig {
            advice: [col_username, col_balance],
            instance,
        }
    }

    pub fn assign_generic_row(
        &self,
        mut layouter: impl Layouter<F>,
        username: Value<F>,
        balance: Value<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "generic row",
            |mut region| {
                // Assign the value to username and balance to the cell inside the region
                region.assign_advice(|| "username", self.config.advice[0], 0, || username)?;

                region.assign_advice(|| "balance", self.config.advice[1], 0, || balance)?;

                Ok(())
            },
        )
    }

    pub fn assign_inclusion_check_row(
        &self,
        mut layouter: impl Layouter<F>,
        username: Value<F>,
        balance: Value<F>,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
        layouter.assign_region(
            || "inclusion row",
            |mut region| {
                // Assign the value to username and balance and return assigned cell
                let username_cell = region.assign_advice(
                    || "username", // we are assigning to column a
                    self.config.advice[0],
                    0,
                    || username,
                )?;

                let balance_cell =
                    region.assign_advice(|| "balance", self.config.advice[1], 0, || balance)?;

                Ok((username_cell, balance_cell))
            },
        )
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        public_username_cell: &AssignedCell<F, F>,
        public_balance_cell: &AssignedCell<F, F>,
    ) -> Result<(), Error> {
        // enforce equality between public_username_cell and instance column at row 0
        layouter.constrain_instance(public_username_cell.cell(), self.config.instance, 0)?;
        // enforce equality between balance_username_cell and instance column at row 1
        layouter.constrain_instance(public_balance_cell.cell(), self.config.instance, 1)?;

        Ok(())
    }
}
