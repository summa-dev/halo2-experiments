use std::{marker::PhantomData};

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::*,
    plonk::*,
    poly::Rotation
};

#[derive(Debug, Clone)]
pub struct Hash2Config {
    pub advice: [Column<Advice>; 3],
    pub instance: Column<Instance>,
    pub selector: Selector,
}

#[derive(Debug, Clone)]
pub struct Hash2Chip<F: FieldExt> {
    config: Hash2Config,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Hash2Chip<F> {

    pub fn construct(config:Hash2Config) -> Self {
        Self {
            config,
            _marker: PhantomData
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 3],
        selector: Selector,
        instance: Column<Instance>,
    ) -> Hash2Config {

        let col_a = advice[0];
        let col_b = advice[1];
        let col_c = advice[2];
        let hash_selector = selector;

        // Enable equality on the advice and instance column to enable permutation check
        meta.enable_equality(col_c);
        meta.enable_equality(instance);

        // enforce dummy hash function by creating a custom gate
        meta.create_gate("hash constraint", |meta| {
            // enforce a + b = c, namely a + b - c = 0
            let s = meta.query_selector(hash_selector);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
       
            vec![s * (a + b - c)]
        });

        Hash2Config {
            advice: [col_a, col_b, col_c],
            instance,
            selector: hash_selector,
        }
    }

    pub fn assign_advice_row(   
        &self,
        mut layouter: impl Layouter<F>,
        a: Value<F>,
        b: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {

        layouter.assign_region(|| "adivce row", |mut region| {

            // enable hash selector 
            self.config.selector.enable(&mut region, 0)?;

            // Assign the value to username and balance to the cell inside the region
            region.assign_advice(
                || "a",
                self.config.advice[0], 
                0, 
                || a,
             )?;

             region.assign_advice(
                || "b",
                self.config.advice[1], 
                0, 
                || b,
             )?;

            let c_cell = region.assign_advice(
                || "c",
                self.config.advice[2], 
                0, 
                || a + b,
             )?;

             Ok(c_cell)
        })

    }

    // Enforce permutation check between b cell and instance column
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        c_cell: AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(c_cell.cell(), self.config.instance, row)
    }

}