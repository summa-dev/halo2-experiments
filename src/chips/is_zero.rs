use halo2_proofs::{
    arithmetic::Field, circuit::*, halo2curves::pasta::Fp, plonk::*, poly::Rotation,
};

#[derive(Clone, Debug)]
pub struct IsZeroConfig {
    pub value_inv: Column<Advice>,
    pub is_zero_expr: Expression<Fp>,
}

impl IsZeroConfig {
    pub fn expr(&self) -> Expression<Fp> {
        self.is_zero_expr.clone()
    }
}

pub struct IsZeroChip {
    config: IsZeroConfig,
}

impl IsZeroChip {
    pub fn construct(config: IsZeroConfig) -> Self {
        IsZeroChip { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        q_enable: impl FnOnce(&mut VirtualCells<'_, Fp>) -> Expression<Fp>,
        value: impl FnOnce(&mut VirtualCells<'_, Fp>) -> Expression<Fp>,
        value_inv: Column<Advice>,
    ) -> IsZeroConfig {
        let mut is_zero_expr = Expression::Constant(Fp::zero());

        meta.create_gate("is_zero", |meta| {
            //
            // valid | value |  value_inv |  1 - value * value_inv | value * (1 - value* value_inv)
            // ------+-------+------------+------------------------+-------------------------------
            //  yes  |   x   |    1/x     |         0              |  0
            //  no   |   x   |    0       |         1              |  x
            //  yes  |   0   |    0       |         1              |  0
            //  yes  |   0   |    y       |         1              |  0
            //
            let value = value(meta);
            let q_enable = q_enable(meta);
            let value_inv = meta.query_advice(value_inv, Rotation::cur());

            is_zero_expr = Expression::Constant(Fp::one()) - value.clone() * value_inv;
            vec![q_enable * value * is_zero_expr.clone()]
        });

        IsZeroConfig {
            value_inv,
            is_zero_expr,
        }
    }

    pub fn assign(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        value: Value<Fp>,
    ) -> Result<(), Error> {
        let value_inv = value.map(|value| value.invert().unwrap_or(Fp::zero()));
        region.assign_advice(|| "value inv", self.config.value_inv, offset, || value_inv)?;
        Ok(())
    }
}
