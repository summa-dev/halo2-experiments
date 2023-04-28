use super::super::chips::add_carry_v1::{AddCarryChip, AddCarryConfig};

use halo2_proofs::{circuit::*, halo2curves::pasta::Fp, plonk::*};

#[derive(Default)]
struct AddCarryCircuit {
    pub a: Vec<Value<Fp>>,
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
        let constant = meta.fixed_column();
        let carry_selector = meta.complex_selector();
        let instance = meta.instance_column();

        AddCarryChip::configure(meta, [col_a, col_b, col_c], constant, carry_selector, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = AddCarryChip::construct(config);

        let (mut prev_b, mut prev_c) = chip.assign_first_row(layouter.namespace(|| "load first row"))?;

        for (i, a) in self.a.iter().enumerate() {
            let (b, c) = chip.assign_advice_row(
                layouter.namespace(|| format!("load row {}", i)),
                *a,
                prev_b,
                prev_c,
            )?;
            prev_b = b;
            prev_c = c;
        }

        // check computation result
        chip.expose_public(layouter.namespace(|| "carry check"), &prev_b, 0)?;
        chip.expose_public(layouter.namespace(|| "remain check"), &prev_c, 1)?;
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
        let a = vec![
            Value::known(Fp::from((1 << 16) - 1)),
            Value::known(Fp::from(1)),
        ];
        let public_inputs = vec![Fp::from(1), Fp::from(0)]; // initial accumulated values

        let circuit = AddCarryCircuit { a };
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        prover.assert_satisfied();
        assert_eq!(prover.verify(), Ok(()));
    }
}
