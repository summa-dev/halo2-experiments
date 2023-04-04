use num_bigint::BigUint;
use std::fmt::Debug;

use super::is_zero::{IsZeroChip, IsZeroConfig};
use super::utils::{decompose_bigInt_to_ubits, fp_to_big_uint, value_fp_to_big_uint, range_check_vec};
use halo2_proofs::{circuit::*, halo2curves::pasta::Fp, plonk::*, poly::Rotation};

#[derive(Debug, Clone)]
pub struct SafeAccumulatorConfig<const MAX_BITS: u8, const ACC_COLS: usize> {
    pub update_value: Column<Advice>,
    pub left_most_inv: Column<Advice>,
    pub add_carries: [Column<Advice>; ACC_COLS],
    pub accumulate: [Column<Advice>; ACC_COLS],
    pub instance: Column<Instance>,
    pub is_zero: IsZeroConfig,
    pub selector: [Selector; 2],
}

#[derive(Debug, Clone)]
pub struct SafeACcumulatorChip<const MAX_BITS: u8, const ACC_COLS: usize> {
    config: SafeAccumulatorConfig<MAX_BITS, ACC_COLS>,
}

impl<const MAX_BITS: u8, const ACC_COLS: usize> SafeACcumulatorChip<MAX_BITS, ACC_COLS> {
    pub fn construct(config: SafeAccumulatorConfig<MAX_BITS, ACC_COLS>) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        update_value: Column<Advice>,
        left_most_inv: Column<Advice>,
        add_carries: [Column<Advice>; ACC_COLS],
        accumulate: [Column<Advice>; ACC_COLS],
        selector: [Selector; 2],
        instance: Column<Instance>,
    ) -> SafeAccumulatorConfig<MAX_BITS, ACC_COLS> {
        let add_carry_selector = selector[0];
        let overflow_check_selector = selector[1];

        let is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(overflow_check_selector),
            |meta| meta.query_advice(accumulate[0], Rotation::cur()),
            left_most_inv,
        );

        // Enable equality on the advice and instance column to enable permutation check
        meta.enable_equality(instance);
        meta.enable_equality(update_value);
        meta.enable_equality(left_most_inv);
        accumulate.map(|col| meta.enable_equality(col));
        add_carries.map(|col| meta.enable_equality(col));

        meta.create_gate("accumulation constraint", |meta| {
            let s_add = meta.query_selector(add_carry_selector);
            let s_over = meta.query_selector(overflow_check_selector);

            // value to be added
            let value = meta.query_advice(update_value, Rotation::cur());

            let previous_acc = (0..ACC_COLS)
                .map(|i| meta.query_advice(accumulate[i], Rotation::prev()))
                .collect::<Vec<Expression<Fp>>>();
            let carries_acc = (0..ACC_COLS)
                .map(|i| meta.query_advice(add_carries[i], Rotation::cur()))
                .collect::<Vec<Expression<Fp>>>();
            let updated_acc = (0..ACC_COLS)
                .map(|i| meta.query_advice(accumulate[i], Rotation::cur()))
                .collect::<Vec<Expression<Fp>>>();

            let shift_next_chunk = Expression::Constant(Fp::from(1 << MAX_BITS));

            // Add the value with right most accumulation column
            let check_add_value_exprs = vec![
                s_add.clone()
                    * ((value + previous_acc[ACC_COLS - 1].clone())
                        - ((carries_acc[ACC_COLS - 1].clone() * shift_next_chunk.clone())
                            + updated_acc[ACC_COLS - 1].clone())),
            ];
            // Check with other accumulation columns with carries
            let check_accumulates_with_carries_expr = (1..ACC_COLS - 1)
                .map(|i| {
                    s_add.clone()
                        * ((updated_acc[i].clone() + (carries_acc[i].clone() * shift_next_chunk.clone()))
                            - (previous_acc[i].clone() + carries_acc[i + 1].clone()))
                })
                .collect::<Vec<Expression<Fp>>>();

            let check_overflow_expr =
                vec![s_over.clone() * (Expression::Constant(Fp::one()) - is_zero.expr())];

            [
                check_add_value_exprs,
                check_accumulates_with_carries_expr,
                check_overflow_expr,
                range_check_vec(&s_over, previous_acc, 1 << MAX_BITS),
                range_check_vec(&s_over, updated_acc, 1 << MAX_BITS),
            ]
            .concat()
        });

        SafeAccumulatorConfig {
            update_value,
            left_most_inv,
            add_carries,
            accumulate,
            instance,
            selector: [add_carry_selector, overflow_check_selector],
            is_zero,
        }
    }

    pub fn assign(
        &self,
        mut layouter: impl Layouter<Fp>,
        offset: usize,
        update_value: Value<Fp>,
        accumulated_values: [Value<Fp>; ACC_COLS], // ) -> Result<[AssignedCell<Fp, Fp>; ACC_COLS], Error> {
    ) -> Result<[Value<Fp>; ACC_COLS], Error> {
        let mut sum = Fp::zero();
        update_value.as_ref().map(|f| sum = sum.add(f));
        assert!(
            sum <= Fp::from(1 << MAX_BITS),
            "update value should less than or equal 2^{MAX_BITS}"
        );

        let is_zero_chip = IsZeroChip::construct(self.config.is_zero.clone());
        layouter.assign_region(
            || "calculate accumulates",
            |mut region| {
                // enable selector
                self.config.selector[0].enable(&mut region, offset + 1)?;
                self.config.selector[1].enable(&mut region, offset + 1)?;

                let mut sum_big_uint = fp_to_big_uint(&sum);

                // Assign new value to the cell inside the region
                region.assign_advice(
                    || "assign value for adding",
                    self.config.update_value,
                    1,
                    || update_value,
                )?;

                // Assign previous accumulation
                for (idx, val) in accumulated_values.iter().enumerate() {
                    let _ = region.assign_advice(
                        || format!("assign previous accumulate[{}] col", idx),
                        self.config.accumulate[idx],
                        0,
                        || *val,
                    )?;
                }

                // Calculates updated accumulate value
                for (idx, acc_val) in accumulated_values.iter().enumerate().rev() {
                    let shift_bits = MAX_BITS as usize * ((ACC_COLS - 1) - idx);
                    sum_big_uint += value_fp_to_big_uint(*acc_val) << shift_bits;

                    // calculate carried sum and assign
                    // if `sum_big_uint` is higher than `1 << shift_bits` assign carried value 1
                    let mut carry_flag = Fp::zero();
                    let shift_mask = BigUint::new(vec![1 << (MAX_BITS as usize + shift_bits)]);
                    if sum_big_uint >= shift_mask && idx > 0 {
                        carry_flag = Fp::one();
                    }

                    let _ = region.assign_advice(
                        || format!("assign carried value at [{}]", idx),
                        self.config.add_carries[idx],
                        offset + 1,
                        || Value::known(carry_flag.clone()),
                    );
                }

                // decomposed result is little-endian, so the vector is opposite to the order of the columns
                let decomposed_sum_big_uint = decompose_bigInt_to_ubits(&sum_big_uint, ACC_COLS, MAX_BITS as usize);

                let mut updated_accumulates: [Value<Fp>; ACC_COLS] = [Value::known(Fp::zero()); ACC_COLS];
                let left_most_idx = ACC_COLS - 1;
                for (i, v) in decomposed_sum_big_uint.iter().enumerate() {
                    // a value in left most columns is overflow
                    if i == left_most_idx {
                        let _is_overflow =
                            is_zero_chip.assign(&mut region, 1, Value::known(v.clone()));
                    }
                    let _cell = region.assign_advice(
                        || format!("assign updated value to accumulated[{}]", i),
                        self.config.accumulate[left_most_idx - i],
                        offset + 1,
                        || Value::known(v.clone()),
                    );
                    updated_accumulates[left_most_idx - i] = Value::known(v.clone());
                }

                Ok(updated_accumulates)
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
