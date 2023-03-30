use halo2_proofs::{
    arithmetic::Field, circuit::*, halo2curves::pasta::Fp, plonk::*, poly::Rotation,
};

#[derive(Debug, Clone)]
pub struct OverFlowCheckConfig {
    pub advice: [Column<Advice>; 5],
    pub instance: Column<Instance>,
    pub selector: Selector,
}

#[derive(Debug, Clone)]
pub struct OverFlowChip {
    config: OverFlowCheckConfig,
}

impl OverFlowChip {
    pub fn construct(config: OverFlowCheckConfig) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        advice: [Column<Advice>; 5],
        selector: Selector,
        instance: Column<Instance>,
    ) -> OverFlowCheckConfig {
        let col_a = advice[0];
        let col_b_inv = advice[1];
        let col_b = advice[2];
        let col_c = advice[3];
        let col_d = advice[4];
        let add_carry_selector = selector;

        // Enable equality on the advice and instance column to enable permutation check
        meta.enable_equality(col_a);
        meta.enable_equality(col_b_inv);
        meta.enable_equality(col_b);
        meta.enable_equality(col_c);
        meta.enable_equality(col_d);
        meta.enable_equality(instance);

        // enforce dummy hash function by creating a custom gate
        meta.create_gate("accumulate constraint", |meta| {
            let s = meta.query_selector(add_carry_selector);
            let prev_b = meta.query_advice(col_b, Rotation::prev());
            let prev_c = meta.query_advice(col_c, Rotation::prev());
            let prev_d = meta.query_advice(col_d, Rotation::prev());
            let a = meta.query_advice(col_a, Rotation::cur());
            let b_inv = meta.query_advice(col_b_inv, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            let d = meta.query_advice(col_d, Rotation::cur());

            // Previous accumulator amount + new value from a_cell
            // using binary expression (x_n-4 * 2^16) + (x_n-3 * 2^8) + ... + (x_n * 2)
            vec![
                s.clone()
                    * ((a
                        + (prev_b * Expression::Constant(Fp::from(1 << 32)))
                        + (prev_c * Expression::Constant(Fp::from(1 << 16)))
                        + prev_d)
                        - ((b.clone() * Expression::Constant(Fp::from(1 << 32)))
                            + (c * Expression::Constant(Fp::from(1 << 16)))
                            + d)),
                // check 'b' is zero
                s * b.clone() * (Expression::Constant(Fp::one()) - b.clone() * b_inv),
            ]
        });

        OverFlowCheckConfig {
            advice: [col_a, col_b_inv, col_b, col_c, col_d],
            instance,
            selector: add_carry_selector,
        }
    }

    // Initial accumulator values from instance for expreiment
    pub fn assign_first_row(
        &self,
        mut layouter: impl Layouter<Fp>,
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
                let b_cell = region.assign_advice_from_instance(
                    || "first acc[2]",
                    self.config.instance,
                    0,
                    self.config.advice[2],
                    0,
                )?;

                let c_cell = region.assign_advice_from_instance(
                    || "first acc[4]",
                    self.config.instance,
                    0,
                    self.config.advice[3],
                    0,
                )?;

                let d_cell = region.assign_advice_from_instance(
                    || "first acc[4]",
                    self.config.instance,
                    1,
                    self.config.advice[4],
                    0,
                )?;

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
        layouter.assign_region(
            || "adivce row for accumulating",
            |mut region| {
                // enable hash selector
                self.config.selector.enable(&mut region, 1)?;

                let _ = prev_b.copy_advice(|| "prev_b", &mut region, self.config.advice[2], 0);
                let _ = prev_c.copy_advice(|| "prev_c", &mut region, self.config.advice[3], 0);
                let _ = prev_d.copy_advice(|| "prev_d", &mut region, self.config.advice[4], 0);

                // Assign new amount to the cell inside the region
                region.assign_advice(|| "a", self.config.advice[0], 1, || a)?;

                let (mid, lo) = self.add_carry::<16>(prev_c.clone(), prev_d.clone(), a);

                // assigning two columns of accumulating value
                // TODO: this might change
                let mut c_cell = region.assign_advice(
                    || "sum_mid",
                    self.config.advice[3],
                    1,
                    || Value::known(mid),
                )?;
                let d_cell = region.assign_advice(
                    || "sum_lo",
                    self.config.advice[4],
                    1,
                    || Value::known(lo),
                )?;

                let mut hi = Fp::zero();
                if mid >= Fp::from(1 << 16) {
                    let (staged_hi, staged_mid) = self.add_carry::<16>(
                        prev_b.clone(),
                        c_cell.clone(),
                        Value::known(Fp::zero()),
                    );
                    hi = staged_hi;
                    c_cell = region.assign_advice(
                        || "sum_mid",
                        self.config.advice[3],
                        1,
                        || Value::known(staged_mid),
                    )?;
                }

                let b_cell = region.assign_advice(
                    || "sum_hi",
                    self.config.advice[2],
                    1,
                    || Value::known(hi),
                )?;

                let b_inv = Value::known(hi).map(|value| value.invert().unwrap_or(Fp::zero()));

                region.assign_advice(|| "b inv", self.config.advice[1], 1, || b_inv)?;

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
