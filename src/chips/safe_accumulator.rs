use arrayvec::ArrayVec;
use eth_types::Field;
use num_bigint::BigUint;
use std::char::MAX;
use std::fmt::Debug;

use super::is_zero::{IsZeroChip, IsZeroConfig};
use super::utils::{
    decompose_bigInt_to_ubits, f_to_big_uint, range_check, range_check_vec, value_f_to_big_uint,
};
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};

#[derive(Debug, Clone)]
pub struct SafeAccumulatorConfig<const MAX_BITS: u8, const ACC_COLS: usize, F: Field> {
    pub update_value: Column<Advice>,
    pub left_most_inv: Column<Advice>,
    pub add_carries: [Column<Advice>; ACC_COLS],
    pub accumulate: [Column<Advice>; ACC_COLS],
    pub instance: Column<Instance>,
    pub is_zero: IsZeroConfig<F>,
    pub selector: [Selector; 2],
}

#[derive(Debug, Clone)]
pub struct SafeACcumulatorChip<const MAX_BITS: u8, const ACC_COLS: usize, F: Field> {
    config: SafeAccumulatorConfig<MAX_BITS, ACC_COLS, F>,
}

impl<const MAX_BITS: u8, const ACC_COLS: usize, F: Field>
    SafeACcumulatorChip<MAX_BITS, ACC_COLS, F>
{
    pub fn construct(config: SafeAccumulatorConfig<MAX_BITS, ACC_COLS, F>) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        update_value: Column<Advice>,
        left_most_inv: Column<Advice>,
        add_carries: [Column<Advice>; ACC_COLS],
        accumulate: [Column<Advice>; ACC_COLS],
        selector: [Selector; 3],
        instance: Column<Instance>,
    ) -> SafeAccumulatorConfig<MAX_BITS, ACC_COLS, F> {
        let bool_selector = selector[0];
        let add_carry_selector = selector[1];
        let overflow_check_selector = selector[2];

        let is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(overflow_check_selector),
            |meta| meta.query_advice(accumulate[0], Rotation::cur()),
            left_most_inv,
        );

        // Enable equality on the advice and instance column to enable permutation check
        accumulate.map(|col| meta.enable_equality(col));
        add_carries.map(|col| meta.enable_equality(col));

        meta.enable_equality(instance);

        meta.create_gate("bool constraint", |meta| {
            let mut exprs: Vec<Expression<F>> = vec![];

            let s = meta.query_selector(bool_selector);

            for carries in add_carries {
                let a = meta.query_advice(carries, Rotation::cur());
                exprs.push(s.clone() * a.clone() * (Expression::Constant(F::from(1)) - a));
            }

            exprs
        });

        meta.create_gate("accumulation constraint", |meta| {
            let s_add = meta.query_selector(add_carry_selector);
            let s_over = meta.query_selector(overflow_check_selector);

            // value to be added
            let value = meta.query_advice(update_value, Rotation::cur());

            let previous_acc = (0..ACC_COLS)
                .map(|i| meta.query_advice(accumulate[i], Rotation::prev()))
                .collect::<Vec<Expression<F>>>();
            let carries_acc = (0..ACC_COLS)
                .map(|i| meta.query_advice(add_carries[i], Rotation::cur()))
                .collect::<Vec<Expression<F>>>();
            let updated_acc = (0..ACC_COLS)
                .map(|i| meta.query_advice(accumulate[i], Rotation::cur()))
                .collect::<Vec<Expression<F>>>();

            let shift_next_chunk = Expression::Constant(F::from(1 << MAX_BITS));

            // Add the value to the rightmost accumulation column.
            //
            // For example, let's assume that each accumulate column has a maximum value of 0xf.
            // For the purpose of explanation, we'll mark the target accumulate column with a cursor represented by ↓↓↓↓↓↓↓↓↓↓↓↓.
            //
            // If we add the value 0x5 to the decomposition of `previous_acc` which has the values `0xed` in the `accumulate_1` and `accumulate_0` columns.
            //                                                                                                                             ↓↓↓↓↓↓↓↓↓↓↓↓
            // | -             | new_value | left_most_inv | add_carries_2 | add_carries_1 | add_carries_0 | accumulate_2 | accumulate_1 | accumulate_0 | add_selector |
            // | --            | --        | --            | --            | --            | --            | --           | --           | -            | -            |
            // | previous_acc  |           |               |               |               |               | 0            | 0xe          | → 0xd        | 0            |
            // | updated_acc   | → 0x5     | 0             | 0             | 0             | 1 ←           | 0            | 0xf          | 2   ←        | 1            |
            //
            // In this case, the result is that `0xd + 0x5 = 0x12`.
            // The first digit of the result, '0x12', is 0x1, which is assigned to the add_carries_0 column, and the rest of the result, 0x2, is placed in the accumulate_0 column.
            // In other words, the sum of the value between the rightmost value of the accumulate columns and the value of new_value is divided into the carry and the remainder.
            //
            // Note that `←` and `→` are used to distinguish between addition and subtraction in the constraints.
            //
            let check_add_value_exprs = vec![
                s_add.clone()
                    * ((value.clone() + previous_acc[ACC_COLS - 1].clone())
                        - ((carries_acc[ACC_COLS - 1].clone() * shift_next_chunk.clone())
                            + updated_acc[ACC_COLS - 1].clone())),
            ];
            let check_range_add_value = vec![s_add.clone() * range_check(value, 1 << MAX_BITS)];

            // Check with other accumulation columns with carries
            //
            // In same circuit configuration above, starting with left most of accumulate columns, `accumulate_2`.
            //                                                                                              ↓↓↓↓↓↓↓↓↓↓↓↓
            // | -             | new_value | left_most_inv | add_carries_2 | add_carries_1 | add_carries_0 | accumulate_2 | accumulate_1 | accumulate_0 | add_selector |
            // | --            | --        | --            | --            | --            | --            | --           | --           | -            | -            |
            // | previous_acc  |           |               |               |               |               | 0 ←          | 0xe          | 0xd          | 0            |
            // | updated_acc   | 0x5       | 0             | → 0           | 0 ←           | 1             | → 0          | 0xf          | 1            | 1            |
            //
            // In here, the constraints easliy staisfy like this `(0x0 + 0x0) - (0x0 + (0 * (1 << 4))) = 0`.
            //
            // In the next iteration, move the cursor to the next accumulate column, `accumulate_1`.
            // add `add_accries_0` to previou accumulate number `0xe` then check equality with updated accumulate number `0xf` at `updated_acc` accumulate_1[1]
            //                                                                                                              ↓↓↓↓↓↓↓↓↓↓↓↓
            // | -             | new_value | left_most_inv | add_carries_2 | add_carries_1 | add_carries_0 | accumulate_2 | accumulate_1 | accumulate_0 | add_selector |
            // | --            | --        | --            | --            | --            | --            | --           | --           | -            | -            |
            // | previous_acc  |           |               |               |               |               | 0            | 0xe ←        | 0xd          | 0            |
            // | updated_acc   | 0x5       | 0             | 0             | → 0           | 1 ←           | 0            | → 0xf        | 1            | 1            |
            //
            // In here, the constraint satisfy that like this `(0xe + 0x1) - (0xf + (0 * (1 << 4))) = 0`
            //
            let check_accumulates_with_carries_expr = (0..ACC_COLS - 1)
                .map(|i| {
                    s_add.clone()
                        * ((updated_acc[i].clone()
                            + (carries_acc[i].clone() * shift_next_chunk.clone()))
                            - (previous_acc[i].clone() + carries_acc[i + 1].clone()))
                })
                .collect::<Vec<Expression<F>>>();

            let check_overflow_expr =
                vec![s_over.clone() * (Expression::Constant(F::one()) - is_zero.expr())];

            [
                check_add_value_exprs,
                check_range_add_value,
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
        mut layouter: impl Layouter<F>,
        offset: usize,
        update_value: Value<F>,
        accumulated_values: [Value<F>; ACC_COLS],
    ) -> Result<(ArrayVec<AssignedCell<F, F>, ACC_COLS>, [Value<F>; ACC_COLS]), Error> {
        let mut sum = F::zero();
        update_value.as_ref().map(|f| sum = sum.add(f));

        let is_zero_chip = IsZeroChip::construct(self.config.is_zero.clone());
        layouter.assign_region(
            || "calculate accumulates",
            |mut region| {
                // enable selector
                self.config.selector[0].enable(&mut region, offset + 1)?;
                self.config.selector[1].enable(&mut region, offset + 1)?;

                let mut sum_big_uint = f_to_big_uint(&sum);

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
                    sum_big_uint += value_f_to_big_uint(*acc_val) << shift_bits;

                    // calculate carried sum and assign
                    // if `sum_big_uint` is higher than `1 << shift_bits` assign carried value 1
                    let mut carry_flag = F::zero();
                    let shift_mask = BigUint::new(vec![1 << (MAX_BITS as usize + shift_bits)]);
                    if sum_big_uint >= shift_mask && idx > 0 {
                        carry_flag = F::one();
                    }

                    let _ = region.assign_advice(
                        || format!("assign carried value at [{}]", idx),
                        self.config.add_carries[idx],
                        offset + 1,
                        || Value::known(carry_flag.clone()),
                    );
                }

                // decomposed result is little-endian, so the vector is opposite to the order of the columns
                let decomposed_sum_big_uint: Vec<F> =
                    decompose_bigInt_to_ubits(&sum_big_uint, ACC_COLS, MAX_BITS as usize);

                let mut updated_accumulates: [Value<F>; ACC_COLS] =
                    [Value::known(F::zero()); ACC_COLS];
                let mut assigned_cells: ArrayVec<AssignedCell<F, F>, ACC_COLS> = ArrayVec::new();
                let left_most_idx = ACC_COLS - 1;
                for (i, v) in decomposed_sum_big_uint.iter().enumerate() {
                    // a value in left most columns is overflow
                    if i == left_most_idx {
                        is_zero_chip.assign(&mut region, 1, Value::known(v.clone()))?;
                    }
                    let cell = region.assign_advice(
                        || format!("assign updated value to accumulated[{}]", i),
                        self.config.accumulate[left_most_idx - i],
                        offset + 1,
                        || Value::known(v.clone()),
                    );
                    assigned_cells.push(cell.unwrap());
                    updated_accumulates[left_most_idx - i] = Value::known(v.clone());
                }
                // query assgiend cells via region
                Ok((assigned_cells, updated_accumulates))
            },
        )
    }

    // Enforce permutation check between b & cell and instance column
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        cell: &AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}
