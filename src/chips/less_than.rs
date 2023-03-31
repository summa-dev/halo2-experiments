use std::marker::PhantomData;

use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};

// take an value in the `input` advice column
// the goal is to check whether the value is less than target
// table is the instance column that contains all the values from 0 to (instance-1)
// advice_table gets dynamically filled with the values from table
// The chip checks that the input value is less than the target value
// This gets done by performing a lookup between the input value and the advice_table

#[derive(Debug, Clone)]
pub struct LessThanConfig {
    input: Column<Advice>,
    table: Column<Instance>,
    advice_table: Column<Advice>,
    q_selector: Selector
}

#[derive(Debug, Clone)]
pub struct LessThanChip<F: FieldExt> {
    config: LessThanConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> LessThanChip<F> {
    pub fn construct(config: LessThanConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        input: Column<Advice>,
        table: Column<Instance>,
    ) -> LessThanConfig {

        let q_selector = meta.complex_selector();
        let advice_table = meta.advice_column();
        meta.enable_equality(table);
        meta.enable_equality(advice_table);
        meta.annotate_lookup_any_column(advice_table, || "Adv-table");

        // Dynamic lookup check
        // TO DO: does it mean that we looking up input inside advice_table?
        meta.lookup_any(
            "dynamic lookup range check", 
            |meta| {
                let q_selector = meta.query_selector(q_selector);
                let input = meta.query_advice(input, Rotation::cur());
                let advice_table = meta.query_advice(advice_table, Rotation::cur());
                vec![(q_selector * input, advice_table)]
            }
        );

        LessThanConfig {
            input,
            table,
            advice_table,
            q_selector
        }
    }

    pub fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        input: Value<F>
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "less than assignment",
            |mut region| {

                // enable selector 
                self.config.q_selector.enable(&mut region, 0)?;

                for i in 0..20 {
                    // Load Advice lookup table with Instance lookup table values.
                    region.assign_advice_from_instance(
                        || "Advice from instance tables",
                        self.config.table,
                        i,
                        self.config.advice_table,
                        i,
                    )?;
                }

                // assign input value to input column
                region.assign_advice(|| "input", self.config.input, 0, || input)?;

                Ok(())
            },
        )
    }
}
