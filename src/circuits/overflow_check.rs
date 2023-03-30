use super::super::chips::overflow_check::{OverFlowCheckConfig, OverFlowChip};

use halo2_proofs::{circuit::*, halo2curves::pasta::Fp, plonk::*};

#[derive(Default)]
struct OverflowCheckCircuit {
    pub a: Value<Fp>,
}

impl Circuit<Fp> for OverflowCheckCircuit {
    type Config = OverFlowCheckConfig;
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
        let carry_selector = meta.complex_selector();
        let instance = meta.instance_column();

        OverFlowChip::configure(
            meta,
            [col_a, col_b_inv, col_b, col_c, col_d],
            carry_selector,
            instance,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = OverFlowChip::construct(config);

        let (prev_b, prev_c, prev_d) =
            chip.assign_first_row(layouter.namespace(|| "load first row"))?;
        println!("prev_b: {:?}", prev_b);
        println!("prev_c: {:?}", prev_c);
        println!("prev_d: {:?}", prev_d);
        let (b, c, d) = chip.assign_advice_row(
            layouter.namespace(|| "load row"),
            self.a,
            prev_b.clone(),
            prev_c.clone(),
            prev_d,
        )?;

        println!("updated b: {:?}", b);
        println!("updated c: {:?}", c);
        println!("updated d: {:?}", d);

        // check computation result
        chip.expose_public(layouter.namespace(|| "carry check"), &b, 2)?;
        chip.expose_public(layouter.namespace(|| "remain check"), &c, 3)?;
        chip.expose_public(layouter.namespace(|| "remain check"), &d, 4)?;
        Ok(())
    }
}

mod tests {
    use super::OverflowCheckCircuit;
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};
    #[test]
    fn test_overflow_check() {
        let k = 4;

        // a: new value
        // public_input[0]: x * 2^16
        // public_input[1]: x * 2^0
        //
        let a = Value::known(Fp::from((1 << 32) + 3));
        let public_inputs = vec![
            // initiali value
            Fp::from(0),
            Fp::from((1 << 16) - 2),

            // checking value
            Fp::from(1),
            Fp::from(1),
            Fp::from(1),
        ]; // initial accumulated values

        let circuit = OverflowCheckCircuit { a };
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        prover.assert_satisfied();
        assert_eq!(prover.verify(), Ok(()));
    }
}
