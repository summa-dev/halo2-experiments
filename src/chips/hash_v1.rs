use std::marker::PhantomData;

use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};

#[derive(Debug, Clone)]
pub struct Hash1Config {
    pub advice: [Column<Advice>; 2],
    pub instance: Column<Instance>,
    pub selector: Selector,
}

#[derive(Debug, Clone)]
pub struct Hash1Chip<F: FieldExt> {
    config: Hash1Config,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Hash1Chip<F> {
    pub fn construct(config: Hash1Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
        instance: Column<Instance>,
    ) -> Hash1Config {
        let col_a = advice[0];
        let col_b = advice[1];

        // create check selector 
        let hash_selector = meta.selector();

        // Enable equality on the advice and instance column to enable permutation check
        meta.enable_equality(col_b);
        meta.enable_equality(instance);

        // enforce dummy hash function by creating a custom gate
        meta.create_gate("hash constraint", |meta| {
            // enforce 2 * a = b, namely 2 * a - b = 0

            let s = meta.query_selector(hash_selector);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());

            vec![s * (Expression::Constant(F::from(2)) * a - b)]
        });

        Hash1Config {
            advice: [col_a, col_b],
            instance,
            selector: hash_selector,
        }
    }

    pub fn assign_advice_row(
        &self,
        mut layouter: impl Layouter<F>,
        a: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "adivce row",
            |mut region| {
                // enable hash selector
                self.config.selector.enable(&mut region, 0)?;

                // Assign the value to username and balance to the cell inside the region
                region.assign_advice(|| "a", self.config.advice[0], 0, || a)?;

                let b_cell = region.assign_advice(
                    || "b",
                    self.config.advice[1],
                    0,
                    || a * Value::known(F::from(2)),
                )?;

                Ok(b_cell)
            },
        )
    }

    // Enforce permutation check between b cell and instance column
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        b_cell: &AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(b_cell.cell(), self.config.instance, row)
    }
}
