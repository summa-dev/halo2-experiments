use crate::chips::utils::{decompose_bigInt_to_ubits, value_fp_to_big_uint};

use super::super::chips::overflow_check_v2::{OverflowCheckV2Config, OverflowChipV2};

use halo2_proofs::{circuit::*, halo2curves::pasta::Fp, plonk::*};

#[derive(Default)]
struct OverflowCheckCircuitV2 {
    pub a: Value<Fp>,
    pub b: Value<Fp>,
}

impl Circuit<Fp> for OverflowCheckCircuitV2 {
    type Config = OverflowCheckV2Config<4, 4>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let col_d = meta.advice_column();
        let col_e = meta.advice_column();
        let selector = meta.selector();
        let instance = meta.instance_column();

        OverflowChipV2::configure(
            meta,
            col_a,
            [col_b, col_c, col_d, col_e],
            instance,
            selector,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = OverflowChipV2::construct(config);

        // check overflow
        chip.assign(
            layouter.namespace(|| "checking overflow value a"),
            self.a
        )?;
        chip.assign(
            layouter.namespace(|| "checking overflow value b"),
            self.b,
        )?;
        chip.assign(
            layouter.namespace(|| "checking overflow value a + b"),
            self.a + self.b,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::OverflowCheckCircuitV2;
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};
    #[test]
    fn test_none_overflow_case() {
        let k = 4;

        // a: new value
        let a = Value::known(Fp::from((1 << 16) - 2));
        let b = Value::known(Fp::from(1));

        let circuit = OverflowCheckCircuitV2 { a, b };
        let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_overflow_case() {
        let k = 4;

        // a: new value
        let a = Value::known(Fp::from((1 << 16) - 2));
        let b = Value::known(Fp::from(3));

        let circuit = OverflowCheckCircuitV2 { a, b };
        let invalid_prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
        assert!(invalid_prover.verify().is_err());
    }
}
