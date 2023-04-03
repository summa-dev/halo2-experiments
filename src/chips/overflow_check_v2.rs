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
        println!("accumulation columns: {:?}", accumulate);

        let add_carry_selector = selector[0];
        let overflow_check_selector = selector[1];

        let is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(overflow_check_selector),
            |meta| meta.query_advice(accumulate[0], Rotation::cur()),
            // |meta| meta.query_advice(col_b_inv, Rotation::cur())
            left_most_inv,
        );

        // Enable equality on the advice and instance column to enable permutation check
        meta.enable_equality(update_value);
        meta.enable_equality(left_most_inv);
        for col in accumulate {
            meta.enable_equality(col);
        }
        meta.enable_equality(instance);

        meta.create_gate("accumulate constraint", |meta| {
            let s_add = meta.query_selector(add_carry_selector);
            let s_over = meta.query_selector(overflow_check_selector);

            let value = meta.query_advice(update_value, Rotation::cur());
            meta.query_advice(left_most_inv, Rotation::cur());
            meta.query_advice(accumulate[0], Rotation::cur());

            // TODO: refactoring
            println!("ACC_COLS: {:?}", ACC_COLS);
            let accumulated_columns = (0..ACC_COLS)
                .map(|i| {
                    let prev = meta.query_advice(accumulate[i], Rotation::prev());
                    let cur = meta.query_advice(accumulate[i], Rotation::cur());
                    (prev, cur)
                })
                .collect::<Vec<(Expression<Fp>, Expression<Fp>)>>();
            println!("accumulated_columns: {:?}", accumulated_columns);
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

            println!("previous_accumulates:\n {:?}", previous_accumulates);
            println!("current_accumulates:\n {:?}", current_accumulates);

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
            println!("sum_of_previous_acc: {:?}", sum_of_previous_acc);
            println!("sum_of_current_acc: {:?}", sum_of_current_acc);

            // Previous accumulator amount + new value from a_cell
            // using binary expression (x_n-4 * 2^16) + (x_n-3 * 2^8) + ... + (x_n * 2)
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

    // Initial accumulator values from instance for expreiment
    pub fn assign_first_row(
        &self,
        mut layouter: impl Layouter<Fp>,
        accumulated_values: Vec<Value<Fp>>,
    ) -> Result<
        (
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
        ),
        Error,
    > {
        layouter.assign_region(
            || "first row",
            |mut region| {
                let b_cell = region.assign_advice(
                    || "first acc[1]",
                    self.config.accumulate[0],
                    0,
                    || accumulated_values[0],
                )?;

                let c_cell = region.assign_advice(
                    || "first acc[2]",
                    self.config.accumulate[1],
                    0,
                    || accumulated_values[1],
                )?;

                let d_cell = region.assign_advice(
                    || "first acc[3]",
                    self.config.accumulate[2],
                    0,
                    || accumulated_values[2],
                )?;
                // let b_cell = region.assign_advice_from_instance(
                //     || "first acc[2]",
                //     self.config.instance,
                //     0,
                //     self.config.advice[2],
                //     0,
                // )?;

                // let c_cell = region.assign_advice_from_instance(
                //     || "first acc[4]",
                //     self.config.instance,
                //     0,
                //     self.config.advice[3],
                //     0,
                // )?;

                // let d_cell = region.assign_advice_from_instance(
                //     || "first acc[4]",
                //     self.config.instance,
                //     1,
                //     self.config.advice[4],
                //     0,
                // )?;

                Ok((b_cell, c_cell, d_cell))
            },
        )
    }

    fn add_carry<const MAX_BITS: u8>(
        &self,
        hi: AssignedCell<Fp, Fp>,
        lo: AssignedCell<Fp, Fp>,
        value: Value<Fp>,
    ) -> (Fp, Fp) {
        let max_bits = Fp::from(1 << MAX_BITS);
        let mut sum = Fp::zero();

        // sum of all values
        value.as_ref().map(|f| sum = sum.add(f));
        hi.value().map(|f| sum = sum.add(&f.mul(&max_bits)));
        lo.value().map(|f| sum = sum.add(f));

        // Iterate sum of all
        let mut remains = sum;
        let mut carry_count = Fp::zero();
        while remains >= max_bits {
            remains = remains.sub(&max_bits);
            carry_count = carry_count.add(&Fp::one());
        }

        (carry_count, remains)
    }

    pub fn assign_advice_row(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: Value<Fp>,
        prev_b: AssignedCell<Fp, Fp>,
        prev_c: AssignedCell<Fp, Fp>,
        prev_d: AssignedCell<Fp, Fp>,
    ) -> Result<
        (
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
        ),
        Error,
    > {
        let is_zero_chip = IsZeroChip::construct(self.config.is_zero.clone());
        layouter.assign_region(
            || "adivce row for accumulating",
            |mut region| {
                // enable hash selector
                self.config.selector[0].enable(&mut region, 1)?;
                self.config.selector[1].enable(&mut region, 1)?;

                let _ = prev_b.copy_advice(|| "prev_b", &mut region, self.config.accumulate[0], 0);
                let _ = prev_c.copy_advice(|| "prev_c", &mut region, self.config.accumulate[1], 0);
                let _ = prev_d.copy_advice(|| "prev_d", &mut region, self.config.accumulate[2], 0); 
                // Assign new value to the cell inside the region
                region.assign_advice(|| "update_value", self.config.update_value, 1, || a)?;

                let (hi, lo) = self.add_carry::<16>(prev_c.clone(), prev_d.clone(), a);

                // assigning two columns of accumulating value
                let mut c_cell = region.assign_advice(
                    || "sum_hi",
                    self.config.accumulate[1],
                    1,
                    || Value::known(hi),
                )?;
                let d_cell = region.assign_advice(
                    || "sum_lo",
                    self.config.accumulate[2],
                    1,
                    || Value::known(lo),
                )?;

                let mut sum_overflow = Fp::zero();
                if hi >= Fp::from(1 << 16) {
                    let (ov, hi) = self.add_carry::<16>(
                        prev_b.clone(),
                        c_cell.clone(),
                        Value::known(Fp::zero()),
                    );
                    sum_overflow = ov;
                    c_cell = region.assign_advice(
                        || "sum_hi",
                        self.config.accumulate[1],
                        1,
                        || Value::known(hi),
                    )?;
                }

                let b_cell = region.assign_advice(
                    || "sum_overflow",
                    self.config.accumulate[0],
                    1,
                    || Value::known(sum_overflow),
                )?;

                // apply is_zero chip in here
                let _is_overflow = is_zero_chip.assign(&mut region, 1, Value::known(hi));

                Ok((b_cell, c_cell, d_cell))
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
