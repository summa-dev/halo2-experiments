use super::super::chips::poseidon::{PoseidonChip, PoseidonConfig};
use halo2_gadgets::poseidon::primitives::*;
use halo2_proofs::{circuit::*, plonk::*, halo2curves::pasta::Fp};
use std::marker::PhantomData;

struct PoseidonCircuit<
    S: Spec<Fp, WIDTH, RATE>,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize,
> {
    hash_input: [Value<Fp>; L],
    digest: Value<Fp>,
    _spec: PhantomData<S>,
}

impl<
        S: Spec<Fp, WIDTH, RATE>,
        const WIDTH: usize,
        const RATE: usize,
        const L: usize,
    > Circuit<Fp> for PoseidonCircuit<S, WIDTH, RATE, L>
{
    type Config = PoseidonConfig<WIDTH, RATE, L>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            hash_input: (0..L)
                .map(|_i| Value::unknown())
                .collect::<Vec<Value<Fp>>>()
                .try_into()
                .unwrap(),
            digest: Value::unknown(),
            _spec: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> PoseidonConfig<WIDTH, RATE, L> {
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let instance = meta.instance_column();

        PoseidonChip::<S, WIDTH, RATE, L>::configure(
            meta,
            state,
            partial_sbox,
            rc_a,
            rc_b,
            instance,
        )
    }

    fn synthesize(
        &self,
        config: PoseidonConfig<WIDTH, RATE, L>,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let poseidon_chip = PoseidonChip::<S, WIDTH, RATE, L>::construct(config);
        let digest = poseidon_chip.hash(layouter.namespace(|| "poseidon chip"), self.hash_input)?;
        poseidon_chip.expose_public(layouter.namespace(|| "expose result"), &digest, 0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;
    use super::PoseidonCircuit;
    use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength, P128Pow5T3};
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};
    #[test]
    fn test_poseidon() {
        let input = 99u64;
        let hash_input = [Fp::from(input), Fp::from(input), Fp::from(input)];

        println!("input: {:?}", Fp::from(input));

        // compute the hash outside of the circuit
        let digest =
            poseidon::Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash(hash_input);

        // print output
        println!("output: {:?}", digest);

        let circuit = PoseidonCircuit::<P128Pow5T3, 3, 2, 3> {
            hash_input: hash_input.map(Value::known),
            digest: Value::known(digest),
            _spec: PhantomData,
        };
        let public_input = vec![digest];
        let prover = MockProver::run(7, &circuit, vec![public_input]).unwrap();
        prover.assert_satisfied();
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_poseidon() {
        use halo2_proofs::halo2curves::pasta::Fp;
        use plotters::prelude::*;

        let root =
            BitMapBackend::new("prints/poseidon-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Posiedon Layout", ("sans-serif", 60)).unwrap();

        let input = 99u64;
        let hash_input = [Fp::from(input), Fp::from(input), Fp::from(input)];

        let digest =
            poseidon::Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash(hash_input);

        let circuit = PoseidonCircuit::<Fp, P128Pow5T3, 3, 2, 3> {
            hash_input: hash_input.map(|x| Value::known(x)),
            digest: Value::known(digest),
            _spec: PhantomData,
        };

        halo2_proofs::dev::CircuitLayout::default()
            .render(7, &circuit, &root)
            .unwrap();
    }
}
