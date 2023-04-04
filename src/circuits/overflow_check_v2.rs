use super::super::chips::overflow_check_v2::{OverFlowCheckV2Config, OverFlowChipV2};

use halo2_proofs::{circuit::*, halo2curves::pasta::Fp, plonk::*};



#[derive(Default)]

struct OverflowCheckCircuit {
    pub value: Vec<Value<Fp>>,
    pub accumulated_value: [Value<Fp>; 3],
}


impl Circuit<Fp> for OverflowCheckCircuit {
    type Config = OverFlowCheckV2Config<3>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let col_a = meta.advice_column();
        let col_b_inv = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let col_d = meta.advice_column();
        let carry_selector = meta.selector();
        let overflow_selector = meta.selector();
        let instance = meta.instance_column();

        OverFlowChipV2::<3>::configure(
            meta,
            col_a,
            col_b_inv,
            [col_b, col_c, col_d],
            [carry_selector, overflow_selector],
            instance,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = OverFlowChipV2::construct(config);

        let mut _last_accumulates = chip.assign(
            layouter.namespace(|| "initial rows"),
            0,
            self.value[0],
            self.accumulated_value,
        ).unwrap().as_slice();
        
        // TODO: iterate value and assign to the chip
        Ok(())
    }
}

mod tests {
    use super::OverflowCheckCircuit;
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};

    #[test]
    fn test_none_overflow_case_v2() {
        let k = 8;

        let value = vec![Value::known(Fp::from(4))];
        let accumulated_value = [
            Value::known(Fp::from(0)),
            Value::known(Fp::from((1 << 16) - 2)),
            Value::known(Fp::from((1 << 16) - 3)),
        ];
        let public_inputs = vec![
            Fp::from(0), 
        ];

        let circuit = OverflowCheckCircuit {
            value,
            accumulated_value,
        };
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        prover.assert_satisfied();
        assert_eq!(prover.verify(), Ok(()));
    }
}
