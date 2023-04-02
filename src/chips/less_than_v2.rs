use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation
};

use super::{
    util::{expr_from_bytes, pow_of_two},
};

/// Config for the Lt chip.
#[derive(Clone, Copy, Debug)]
pub struct LtConfig<F, const N_BYTES: usize> {
    /// Denotes the lt outcome. If lhs < rhs then lt == 1, otherwise lt == 0.
    pub lt: Column<Advice>,
    /// Denotes the bytes representation of the difference between lhs and rhs.
    /// Note that the range of each byte is not checked by this config.
    pub diff: [Column<Advice>; N_BYTES],
    /// Denotes the range within which both lhs and rhs lie.
    pub range: F,
}

impl<F: FieldExt, const N_BYTES: usize> LtConfig<F, N_BYTES> {
    /// Returns an expression that denotes whether lhs < rhs, or not.
    pub fn is_lt(&self, meta: &mut VirtualCells<F>, rotation: Option<Rotation>) -> Expression<F> {
        meta.query_advice(self.lt, rotation.unwrap_or_else(Rotation::cur))
    }
}

/// Chip that compares lhs < rhs.
#[derive(Clone, Debug)]
pub struct LtChip<F, const N_BYTES: usize> {
    config: LtConfig<F, N_BYTES>,
}

impl<F: FieldExt, const N_BYTES: usize> LtChip<F, N_BYTES> {

    /// Configures the Lt chip.
    /// takes a few closures as an argument. Each closure nees to implement a specific trait and is expected to return an expression that 
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        lhs: impl FnOnce(&mut VirtualCells<F>) -> Expression<F>,
        rhs: impl FnOnce(&mut VirtualCells<F>) -> Expression<F>,
    ) -> LtConfig<F, N_BYTES> {

        let lt = meta.advice_column();
        let diff = [(); N_BYTES].map(|_| meta.advice_column());

        // if N_BYTES == 1, then range = 2^8 = 256
        let range = pow_of_two(N_BYTES * 8);

        meta.create_gate("lt gate", |meta| {

            let q_enable = q_enable(meta);
            // query the lt advice column => The expression contains the lt outcome
            let lt = meta.query_advice(lt, Rotation::cur());

            // query the diff advice columns => The expression is a vector contains the bytes representation of the difference between lhs and rhs
            let diff_bytes = diff
                .iter()
                .map(|c| meta.query_advice(*c, Rotation::cur()))
                .collect::<Vec<Expression<F>>>();

            let check_a =
                lhs(meta) - rhs(meta) - expr_from_bytes(&diff_bytes) + (lt.clone() * range);

            // constrain that check whether lt is 1 or 0

            [check_a]
                .into_iter()
                .map(move |poly| q_enable.clone() * poly)
        });

        LtConfig { lt, diff, range }
    }

    /// Constructs a Lt chip given a config.
    pub fn construct(config: LtConfig<F, N_BYTES>) -> LtChip<F, N_BYTES> {
        LtChip { config }
    }

    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        lhs: F,
        rhs: F,
    ) -> Result<(), Error> {

        let config = self.config;

        // calculate lt outcome and assign it to the lt advice column
        let lt = lhs < rhs;
        region.assign_advice(
            || "lt chip: lt",
            config.lt,
            offset,
            || Value::known(F::from(lt as u64)),
        )?;

        let diff = (lhs - rhs) + (if lt { config.range } else { F::zero() });
        
        let diff_bytes = diff.to_repr();
        let diff_bytes = diff_bytes.as_ref();
        for (idx, diff_column) in config.diff.iter().enumerate() {
            region.assign_advice(
                || format!("lt chip: diff byte {}", idx),
                *diff_column,
                offset,
                || Value::known(F::from(diff_bytes[idx] as u64)),
            )?;
        }

        Ok(())
    }
}
