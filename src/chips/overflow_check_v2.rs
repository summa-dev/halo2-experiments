use halo2_proofs::{circuit::*, halo2curves::pasta::Fp, plonk::*, poly::Rotation};
use std::fmt::Debug;

use super::utils::{decompose_bigInt_to_ubits, range_check_vec, value_fp_to_big_uint};

#[derive(Debug, Clone)]
pub struct OverflowCheckV2Config<const MAX_BITS: u8, const ACC_COLS: usize> {
    pub value: Column<Advice>,
    pub decomposed_values: [Column<Advice>; ACC_COLS],
    pub instance: Column<Instance>,
    pub selector: Selector,
}

#[derive(Debug, Clone)]
pub struct OverflowChipV2<const MAX_BITS: u8, const ACC_COLS: usize> {
    config: OverflowCheckV2Config<MAX_BITS, ACC_COLS>,
}

impl<const MAX_BITS: u8, const ACC_COLS: usize> OverflowChipV2<MAX_BITS, ACC_COLS> {
    pub fn construct(config: OverflowCheckV2Config<MAX_BITS, ACC_COLS>) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        value: Column<Advice>,
        decomposed_values: [Column<Advice>; ACC_COLS],
        instance: Column<Instance>,
        selector: Selector,
    ) -> OverflowCheckV2Config<MAX_BITS, ACC_COLS> {
        meta.enable_equality(value);
        decomposed_values.map(|col| meta.enable_equality(col));

        meta.create_gate("range check decomposed values", |meta| {
            let s_doc = meta.query_selector(selector);

            let value = meta.query_advice(value, Rotation::cur());

            let decomposed_value_vec = (0..ACC_COLS)
                .map(|i| meta.query_advice(decomposed_values[i], Rotation::cur()))
                .collect::<Vec<_>>();

            let decomposed_value_sum =
                (0..=ACC_COLS - 2).fold(decomposed_value_vec[ACC_COLS - 1].clone(), |acc, i| {
                    acc + (decomposed_value_vec[i].clone()
                        * Expression::Constant(Fp::from(
                            1 << (MAX_BITS as usize * ((ACC_COLS - 1) - i)),
                        )))
                });

            [
                vec![s_doc.clone() * (decomposed_value_sum - value)], // equality check between decomposed value and value
                range_check_vec(&s_doc, decomposed_value_vec, 1 << MAX_BITS), // range check for each decomposed columns
            ]
            .concat()
        });

        OverflowCheckV2Config {
            value,
            decomposed_values,
            instance,
            selector,
        }
    }

    pub fn assign(
        &self,
        mut layouter: impl Layouter<Fp>,
        update_value: Value<Fp>,
        // decomposed_values: Vec<Value<Fp>>
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "assign decomposed values",
            |mut region| {
                // enable selector
                self.config.selector.enable(&mut region, 0)?;

                // Assign input value to the cell inside the region
                region.assign_advice(|| "assign value", self.config.value, 0, || update_value)?;

                // Just used helper function for decomposing. In other halo2 application used functions based on Field.
                let decomposed_values =
                    decompose_bigInt_to_ubits(&value_fp_to_big_uint(update_value), MAX_BITS as usize, ACC_COLS);

                // Note that, decomposed result is little edian. So, we need to reverse it.
                for (idx, val) in decomposed_values.iter().rev().enumerate() {
                    let _cell = region.assign_advice(
                        || format!("assign decomposed[{}] col", idx),
                        self.config.decomposed_values[idx],
                        0,
                        || Value::known(*val),
                    )?;
                }

                Ok(())
            },
        )
    }

    // Enforce permutation check between b & cell and instance column
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        cell: &AssignedCell<Fp, Fp>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}
