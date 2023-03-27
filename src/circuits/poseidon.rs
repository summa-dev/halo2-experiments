/*
An easy-to-use implementation of the Poseidon Hash in the form of a Halo2 Chip. While the Poseidon Hash function
is already implemented in halo2_gadgets, there is no wrapper chip that makes it easy to use in other circuits.
*/

use super::super::chips::poseidon::{PoseidonChip, PoseidonConfig};
use halo2_gadgets::poseidon::{primitives::*};
use halo2_proofs::{circuit::*, plonk::*, halo2curves::pasta::Fp};
use std::marker::PhantomData;

struct PoseidonCircuit<
    S: Spec<Fp, WIDTH, RATE>,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize,
> {
    message: [Value<Fp>; L],
    output: Value<Fp>,
    _spec: PhantomData<S>,
}

impl<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize> Circuit<Fp>
    for PoseidonCircuit<S, WIDTH, RATE, L>
{
    type Config = PoseidonConfig<WIDTH, RATE, L>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            message: (0..L)
                .map(|i| Value::unknown())
                .collect::<Vec<Value<Fp>>>()
                .try_into()
                .unwrap(),
            output: Value::unknown(),
            _spec: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> PoseidonConfig<WIDTH, RATE, L> {
        PoseidonChip::<S, WIDTH, RATE, L>::configure(meta)
    }

    fn synthesize(
        &self,
        config: PoseidonConfig<WIDTH, RATE, L>,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let poseidon_chip = PoseidonChip::<S, WIDTH, RATE, L>::construct(config);
        let message_cells = poseidon_chip
            .load_private_inputs(layouter.namespace(|| "load private inputs"), self.message)?;
        let result = poseidon_chip.hash(layouter.namespace(|| "poseidon chip"), &message_cells)?;
        poseidon_chip.expose_public(layouter.namespace(|| "expose result"), &result, 0)?;
        Ok(())
    }
}

mod tests {
    use std::marker::PhantomData;

    use super::PoseidonCircuit;
    use halo2_gadgets::poseidon::{
        primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
        Hash,
    };
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};
    #[test]
    fn test_poseidon() {
        let input = 99999999u64;
        let message = [Fp::from(input)];
        let output =
            poseidon::Hash::<_, OrchardNullifier, ConstantLength<1>, 3, 2>::init().hash(message);

        // print output 
        println!("input: {:?}", input);
        println!("output: {:?}", output);    

        let circuit = PoseidonCircuit::<OrchardNullifier, 3, 2, 1> {
            message: message.map(|x| Value::known(x)),
            output: Value::known(output),
            _spec: PhantomData,
        };
        let public_input = vec![output];
        let prover = MockProver::run(10, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();
    }
}