use std::marker::PhantomData;

use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};

// take an value in the `input` advice column
// the goal is to check whether the value is less than target
// target is dynamic passed as instance value
// advice_table gets dynamically filled with values from  in the values added to the advice table 
// the table gets filled up dynamically

#[derive(Debug, Clone)]
pub struct LessThanConfig {
    input: Column<Advice>,
    advice_table: Column<Advice>,
    q_selector: Selector
}

#[derive(Debug, Clone)]
pub struct LessThanChip<Fp: FieldExt> {
    config: LessThanConfig,
    _marker: PhantomData<Fp>,
}

impl<Fp: FieldExt> LessThanChip<Fp> {
    pub fn construct(config: LessThanConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        input: Column<Advice>
    ) -> LessThanConfig {

        let q_selector = meta.complex_selector();
        let advice_table = meta.advice_column();
        meta.annotate_lookup_any_column(advice_table, || "Adv-table");

        // Dynamic lookup check
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
            advice_table,
            q_selector
        }
    }

    pub fn assign(
        &self,
        mut layouter: impl Layouter<Fp>,
        input: Value<Fp>,
        // target_value: Value<Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "less than assignment",
            |mut region| {

                // enable selector 
                self.config.q_selector.enable(&mut region, 0)?;

                // assign input value to input column
                region.assign_advice(|| "input", self.config.input, 0, || input)?;

                region.assign_advice(|| "advice look up table", self.config.advice_table, 0, || Value::known(Fp::from(19))
                )?;
                Ok(())
            },
        )
    }
}
