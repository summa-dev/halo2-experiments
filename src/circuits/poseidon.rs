/*
An easy-to-use implementation of the Poseidon Hash in the form of a Halo2 Chip. While the Poseidon Hash function
is already implemented in halo2_gadgets, there is no wrapper chip that makes it easy to use in other circuits.
*/

use super::super::chips::poseidon::{PoseidonChip, PoseidonConfig};
use halo2_gadgets::poseidon::{primitives::*};
use halo2_proofs::{circuit::*, plonk::*, arithmetic::FieldExt};
use std::marker::PhantomData;

struct PoseidonCircuit<
    F: FieldExt,
    S: Spec<F, WIDTH, RATE>,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize,
> {
    message: [Value<F>; L],
    output: Value<F>,
    _spec: PhantomData<S>,
}

impl<F: FieldExt, S: Spec<F, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize> Circuit<F>
    for PoseidonCircuit<F, S, WIDTH, RATE, L>
{
    type Config = PoseidonConfig<F, WIDTH, RATE, L>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            message: (0..L)
                .map(|i| Value::unknown())
                .collect::<Vec<Value<F>>>()
                .try_into()
                .unwrap(),
            output: Value::unknown(),
            _spec: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> PoseidonConfig<F, WIDTH, RATE, L> {
        PoseidonChip::<F, S, WIDTH, RATE, L>::configure(meta)
    }

    fn synthesize(
        &self,
        config: PoseidonConfig<F, WIDTH, RATE, L>,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let poseidon_chip = PoseidonChip::<F, S, WIDTH, RATE, L>::construct(config);
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
        primitives::{self as poseidon, ConstantLength, P128Pow5T3, Spec},
        Hash,
    };
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};
    #[test]
    fn test_poseidon() {
        let input = 99u64;
        let message = [Fp::from(input), Fp::from(input)];
        let output =
            poseidon::Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash(message);

        let circuit = PoseidonCircuit::<Fp, P128Pow5T3, 3, 2, 2> {
            message: message.map(|x| Value::known(x)),
            output: Value::known(output),
            _spec: PhantomData,
        };
        let public_input = vec![output];
        let prover = MockProver::run(10, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();
    }

}