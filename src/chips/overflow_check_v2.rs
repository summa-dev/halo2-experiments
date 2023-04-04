use crate::chips::is_zero;

use super::is_zero::{IsZeroChip, IsZeroConfig};
use halo2_proofs::{
    arithmetic::Field, circuit::*, halo2curves::pasta::Fp, plonk::*, poly::Rotation,
};

#[derive(Debug, Clone)]
pub struct OverFlowCheckV2Config<const ACC_COLS: usize> {
    pub update_value: Column<Advice>,
    pub left_most_inv: Column<Advice>,
    pub accumulate: [Column<Advice>; ACC_COLS],
    pub instance: Column<Instance>,
    pub is_zero: IsZeroConfig,
    pub selector: [Selector; 2],
}

#[derive(Debug, Clone)]
pub struct OverFlowChipV2<const ACC_COLS: usize> {
    config: OverFlowCheckV2Config<ACC_COLS>,
}

impl<const ACC_COLS: usize> OverFlowChipV2<ACC_COLS> {
    pub fn construct(config: OverFlowCheckV2Config<ACC_COLS>) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        update_value: Column<Advice>,
        left_most_inv: Column<Advice>,
        accumulate: [Column<Advice>; ACC_COLS],
        selector: [Selector; 2],
        instance: Column<Instance>,
    ) -> OverFlowCheckV2Config<ACC_COLS> {
        let add_carry_selector = selector[0];
        let overflow_check_selector = selector[1];

        let is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(overflow_check_selector),
            |meta| meta.query_advice(accumulate[0], Rotation::cur()),
            left_most_inv,
        );

        // Enable equality on the advice and instance column to enable permutation check
        meta.enable_equality(update_value);
        meta.enable_equality(left_most_inv);
        for col in accumulate {
            meta.enable_equality(col);
        }
        meta.enable_equality(instance);

        meta.create_gate("accumulation constraint", |meta| {
            let s_add = meta.query_selector(add_carry_selector);
            let s_over = meta.query_selector(overflow_check_selector);

            let value = meta.query_advice(update_value, Rotation::cur());
            meta.query_advice(left_most_inv, Rotation::cur());
            meta.query_advice(accumulate[0], Rotation::cur());

            // TODO: refactoring
            let accumulated_columns = (0..ACC_COLS)
                .map(|i| {
                    let prev = meta.query_advice(accumulate[i], Rotation::prev());
                    let cur = meta.query_advice(accumulate[i], Rotation::cur());
                    (prev, cur)
                })
                .collect::<Vec<(Expression<Fp>, Expression<Fp>)>>();
            let previous_accumulates = accumulated_columns
                .iter()
                .enumerate()
                .map(|(idx, (prev, _))| {
                    let double_bytes_shift = 16 * (ACC_COLS - (idx + 1));
                    prev.clone() * Expression::Constant(Fp::from(1 << double_bytes_shift))
                })
                .collect::<Vec<Expression<Fp>>>();
            let current_accumulates = accumulated_columns
                .iter()
                .enumerate()
                .map(|(idx, (_, cur))| {
                    let double_bytes_shift = 16 * (ACC_COLS - (idx + 1));
                    cur.clone() * Expression::Constant(Fp::from(1 << double_bytes_shift))
                })
                .collect::<Vec<Expression<Fp>>>();

            let sum_of_previous_acc = previous_accumulates
                .iter()
                .fold(Expression::Constant(Fp::zero()), |cur, next| {
                    cur + next.clone()
                });
            let sum_of_current_acc = current_accumulates
                .iter()
                .fold(Expression::Constant(Fp::zero()), |cur, next| {
                    cur + next.clone()
                });

            vec![
                s_add * (value + sum_of_previous_acc - sum_of_current_acc),
                // check 'b' is zero
                s_over * (Expression::Constant(Fp::one()) - is_zero.expr()),
            ]
        });

        OverFlowCheckV2Config {
            update_value,
            left_most_inv,
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
    ) -> Result<Vec<AssignedCell<Fp, Fp>>, Error> {
        // TODO: handling more than 16bits value
        let mut sum = Fp::zero();
        update_value.as_ref().map(|f| sum = sum.add(f));
        assert!(
            sum <= Fp::from(1 << 16),
            "update value less than or equal 2^16"
        );

        let is_zero_chip = IsZeroChip::construct(self.config.is_zero.clone());
        layouter.assign_region(
            || "accumulate",
            |mut region| {
                // enable hash selector
                self.config.selector[0].enable(&mut region, 1)?;
                self.config.selector[1].enable(&mut region, 1)?;

                // Assign new value to the cell inside the region
                region.assign_advice(
                    || "assign value for adding",
                    self.config.update_value,
                    1,
                    || update_value,
                )?;

                // Assign previous accumulation
                for (idx, val) in accumulated_values.iter().enumerate() {
                    region.assign_advice(
                        || format!("assign previous accumulate[{}] col", idx),
                        self.config.accumulate[idx],
                        offset,
                        || *val,
                    )?;
                }

                // TODO: refactoring calculation with closure pattern
                let mut updated_accumulated_value = [Fp::zero(); ACC_COLS];
                let mut carry_value = Fp::zero();

                let _ = (1..ACC_COLS)
                    .map(|idx| {
                        let lhs_idx = ACC_COLS - (idx + 1);
                        let rhs_idx = ACC_COLS - idx;
                        let shift_bits = Fp::from(1 << 16);
                        let mut sum = Fp::zero();

                        // a sum of value in two columns on right side
                        if idx == 1 {
                            accumulated_values[rhs_idx].map(|f| sum = sum.add(&f));
                            update_value.as_ref().map(|f| sum = sum.add(&f));
                        } else {
                            sum = sum.add(&carry_value);
                        }
                        accumulated_values[lhs_idx].map(|f| sum = sum.add(&f.mul(&shift_bits)));

                        // calculate a number for carry to next column
                        carry_value = Fp::zero();
                        let mut remains = sum;
                        while remains >= shift_bits {
                            remains = remains.sub(&shift_bits);
                            carry_value = carry_value.add(&Fp::one());
                        }

                        updated_accumulated_value[rhs_idx] = remains;

                        // Assign left most column for overflow number
                        if lhs_idx == 0 {
                            updated_accumulated_value[0] = carry_value.clone();
                        }
                    })
                    .collect::<Vec<()>>();

                let mut assigend_cells: Vec<AssignedCell<Fp, Fp>> = vec![];
                for (i, v) in updated_accumulated_value.iter().enumerate() {
                    // a value in left most columns is overflow
                    if i == 0 {
                        let _is_overflow =
                            is_zero_chip.assign(&mut region, 1, Value::known(v.clone()));
                    }
                    let _cell = region.assign_advice(
                        || format!("assign updated value to accumulated[{}]", i),
                        self.config.accumulate[i],
                        offset + 1,
                        || Value::known(v.clone()),
                    );
                    assigend_cells.push(_cell.unwrap());
                }

                Ok(assigend_cells)
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
