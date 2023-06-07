use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};

#[derive(Debug, Clone)]
pub struct Hash2Config {
    pub advice: [Column<Advice>; 3],
    pub instance: Column<Instance>,
    pub selector: Selector,
}

#[derive(Debug, Clone)]
pub struct Hash2Chip {
    config: Hash2Config,
}

impl Hash2Chip {
    pub fn construct(config: Hash2Config) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        advice: [Column<Advice>; 3],
        instance: Column<Instance>,
    ) -> Hash2Config {
        let col_a = advice[0];
        let col_b = advice[1];
        let col_c = advice[2];

        // create check selector
        let hash_selector = meta.selector();

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
        mut layouter: impl Layouter<Fp>,
        input: Value<Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || "load private",
            |mut region| {
                region.assign_advice(|| "private input", self.config.advice[0], 0, || input)
            },
        )
    }

    pub fn hash(
        &self,
        mut layouter: impl Layouter<Fp>,
        a_cell: AssignedCell<Fp, Fp>,
        b_cell: AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || "hash row",
            |mut region| {
                // enable hash selector
                self.config.selector.enable(&mut region, 0)?;

                a_cell.copy_advice(|| "input_a", &mut region, self.config.advice[0], 0)?;
                b_cell.copy_advice(|| "input_b", &mut region, self.config.advice[1], 0)?;

                let c_cell = region.assign_advice(
                    || "c",
                    self.config.advice[2],
                    0,
                    || a_cell.value().map(|x| x.to_owned()) + b_cell.value().map(|x| x.to_owned()),
                )?;

                Ok(c_cell)
            },
        )
    }

    // Enforce permutation check between b cell and instance column
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        c_cell: &AssignedCell<Fp, Fp>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(c_cell.cell(), self.config.instance, row)
    }
}
