use super::super::chips::add_carry_v1::{AddCarryChip, AddCarryConfig};

use halo2_proofs::{circuit::*, halo2curves::pasta::Fp, plonk::*};

#[derive(Default)]
struct AddCarryCircuit {
    pub a: Value<Fp>,
}

impl Circuit<Fp> for AddCarryCircuit {
    type Config = AddCarryConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let carry_selector = meta.complex_selector();
        let instance = meta.instance_column();

        AddCarryChip::configure(meta, [col_a, col_b, col_c], carry_selector, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = AddCarryChip::construct(config);

        let (prev_b, prev_c) = chip.assign_first_row(layouter.namespace(|| "load first row"))?;
        let (b, c) =
            chip.assign_advice_row(layouter.namespace(|| "load row"), self.a, prev_b.clone(), prev_c.clone())?;

        // check computation result
        chip.expose_public(layouter.namespace(|| "carry check"), &b, 2)?;
        chip.expose_public(layouter.namespace(|| "remain check"), &c, 3)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::AddCarryCircuit;
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};
    #[test]
    fn test_carry_1() {
        let k = 4;

        // a: new value
        let a = Value::known(Fp::from(1));
        let public_inputs = vec![Fp::from(0), Fp::from((1 << 16) - 1), Fp::from(1), Fp::from(0)];

        let circuit = AddCarryCircuit { a };
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        prover.assert_satisfied();
        assert_eq!(prover.verify(), Ok(()));
    }
}
