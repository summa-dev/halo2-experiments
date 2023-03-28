use super::super::chips::inclusion_check::{InclusionCheckChip, InclusionCheckConfig};

use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*};

#[derive(Default)]

// define circuit struct using array of usernames and balances
struct MyCircuit<F> {
    pub usernames: [Value<F>; 10],
    pub balances: [Value<F>; 10],
    pub inclusion_index: u8,
}

impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
    type Config = InclusionCheckConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let col_username = meta.advice_column();
        let col_balance = meta.advice_column();
        let instance = meta.instance_column();

        InclusionCheckChip::configure(meta, [col_username, col_balance], instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // We create a new instance of chip using the config passed as input
        let chip = InclusionCheckChip::<F>::construct(config);

        // loop over the usernames array and assign the rows
        for _i in 0..self.usernames.len() {
            // if row is equal to the inclusion index, assign the value using the assign_inclusion_check_row function
            // else assign the value using the assign_generic_row function
            if (_i as u8) == self.inclusion_index {
                // extract username and balances cell from here!
                let (username_cell, balance_cell) = chip.assign_inclusion_check_row(
                    layouter.namespace(|| "inclusion row"),
                    self.usernames[_i],
                    self.balances[_i],
                )?;

                // expose the public values
                chip.expose_public(
                    layouter.namespace(|| "expose public"),
                    &username_cell,
                    &balance_cell,
                )?;
            } else {
                chip.assign_generic_row(
                    layouter.namespace(|| "generic row"),
                    self.usernames[_i],
                    self.balances[_i],
                )?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::MyCircuit;
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};
    #[test]
    fn test_inclusion_check_1() {
        let k = 4;

        // initate usernames and balances array
        let mut usernames: [Value<Fp>; 10] = [Value::default(); 10];
        let mut balances: [Value<Fp>; 10] = [Value::default(); 10];

        // add 10 values to the username array and balances array
        for i in 0..10 {
            usernames[i] = Value::known(Fp::from(i as u64));
            balances[i] = Value::known(Fp::from(i as u64) * Fp::from(2));
        }

        // Table is
        // username | balance
        // 0        | 0
        // 1        | 2
        // 2        | 4
        // 3        | 6
        // 4        | 8
        // 5        | 10
        // 6        | 12
        // 7        | 14
        // 8        | 16
        // 9        | 18

        let circuit = MyCircuit::<Fp> {
            usernames,
            balances,
            inclusion_index: 7,
        };

        // Test 1 - Inclusion check on a existing entry for the corresponding inclusion_index
        let public_input_valid = vec![Fp::from(7), Fp::from(14)];
        let prover = MockProver::run(k, &circuit, vec![public_input_valid]).unwrap();
        prover.assert_satisfied();

        // Test 2 - Inclusion check on a existing entry but not for the corresponding inclusion_index
        let public_input_invalid = vec![Fp::from(8), Fp::from(16)];
        let prover = MockProver::run(k, &circuit, vec![public_input_invalid]).unwrap();
        assert!(prover.verify().is_err());

        // Test 3 - Inclusion check on a non-existing entry
        let public_input_invalid2 = vec![Fp::from(10), Fp::from(20)];
        let prover = MockProver::run(k, &circuit, vec![public_input_invalid2]).unwrap();
        assert!(prover.verify().is_err());
    }
}

#[cfg(feature = "dev-graph")]
#[test]
fn print_inclusion_check() {
    use halo2_proofs::{halo2curves::pasta::Fp};
    use plotters::prelude::*;

    let root = BitMapBackend::new("prints/inclusion-check-1-layout.png", (1024, 3096)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root
        .titled("Inclusion Check 1 Layout", ("sans-serif", 60))
        .unwrap();

    let mut usernames: [Value<Fp>; 10] = [Value::known(Fp::from(0)); 10];
    let mut balances: [Value<Fp>; 10] = [Value::known(Fp::from(0)); 10];

    let circuit = MyCircuit::<Fp> {
        usernames,
        balances,
        inclusion_index: 2,
    };

    halo2_proofs::dev::CircuitLayout::default()
        .render(3, &circuit, &root)
        .unwrap();
}
