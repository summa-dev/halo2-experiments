use std::marker::PhantomData;

use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};

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
    pub fn construct(config: Hash2Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
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

        meta.enable_equality(col_a);
        meta.enable_equality(col_b);


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

    pub fn load_private(
        &self,
        mut layouter: impl Layouter<F>,
        input: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "load private",
            |mut region| {
                region.assign_advice(|| "private input", self.config.advice[0], 0, || input)
            },
        )
    }

    pub fn hash(
        &self,
        mut layouter: impl Layouter<F>,
        a_cell: AssignedCell<F, F>,
        b_cell: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "hash row",
            |mut region| {
                // enable hash selector
                self.config.selector.enable(&mut region, 0)?;

                a_cell.copy_advice(|| "input_a", &mut region, self.config.advice[0], 0)?;
                b_cell.copy_advice(|| "input_b", &mut region, self.config.advice[1], 0)?;

                let c_cell = region.assign_advice(|| "c", self.config.advice[2], 0, || {
                    a_cell.value().map(|x| x.to_owned())
                        + b_cell.value().map(|x| x.to_owned())
                })?;

                Ok(c_cell)
            },
        )
    }

    // Enforce permutation check between b cell and instance column
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        c_cell: &AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(c_cell.cell(), self.config.instance, row)
    }
}