use super::super::chips::poseidon::hash_with_instance::{PoseidonChip, PoseidonConfig};
use halo2_gadgets::poseidon::primitives::*;
use halo2_proofs::{circuit::*, arithmetic::FieldExt, plonk::*};
use std::marker::PhantomData;

struct PoseidonCircuit<
    F: FieldExt,
    S: Spec<F, WIDTH, RATE>,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize,
> {
    hash_input: [Value<F>; L],
    digest: Value<F>,
    _spec: PhantomData<S>,
}

impl<F:FieldExt, S: Spec<F, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize> Circuit<F>
    for PoseidonCircuit<F, S, WIDTH, RATE, L>
{
    type Config = PoseidonConfig<F, WIDTH, RATE, L>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            hash_input: (0..L)
                .map(|_i| Value::unknown())
                .collect::<Vec<Value<F>>>()
                .try_into()
                .unwrap(),
            digest: Value::unknown(),
            _spec: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> PoseidonConfig<F, WIDTH, RATE, L> {
        let instance = meta.instance_column();
        let hash_inputs = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();

        PoseidonChip::<F, S, WIDTH, RATE, L>::configure(meta, hash_inputs, instance)
    }

    fn synthesize(
        &self,
        config: PoseidonConfig<F, WIDTH, RATE, L>,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let poseidon_chip = PoseidonChip::<F, S, WIDTH, RATE, L>::construct(config);
        let assigned_input_cells = poseidon_chip.load_private_inputs(
            layouter.namespace(|| "load private inputs"),
            self.hash_input,
        )?;
        let digest = poseidon_chip.hash(
            layouter.namespace(|| "poseidon chip"),
            &assigned_input_cells,
        )?;
        poseidon_chip.expose_public(layouter.namespace(|| "expose result"), &digest, 0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::chips::poseidon::spec::MySpec;
    use super::PoseidonCircuit;
    use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength};
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};
    use std::marker::PhantomData;
    #[test]
    fn test_poseidon() {
        let input = 99u64;
        let hash_input = [
            Fp::from(input),
            Fp::from(input),
            Fp::from(input),
            Fp::from(input),
        ];

        const WIDTH: usize = 5;
        const RATE: usize = 4;
        const L: usize = 4;

        assert_eq!(hash_input.len(), L);
        assert_eq!(WIDTH, hash_input.len() + 1);
        assert_eq!(RATE, hash_input.len());

        // compute the hash outside of the circuit
        let digest =
            poseidon::Hash::<_, MySpec<Fp, WIDTH, RATE>, ConstantLength<L>, WIDTH, RATE>::init()
                .hash(hash_input);

        let circuit = PoseidonCircuit::<Fp, MySpec<Fp, WIDTH, RATE>, WIDTH, RATE, L> {
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
        use super::super::super::chips::poseidon::spec::MySpec;
        use halo2_proofs::halo2curves::pasta::Fp;
        use plotters::prelude::*;

        let root =
            BitMapBackend::new("prints/poseidon-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Posiedon Layout", ("sans-serif", 60)).unwrap();

        let input = 99u64;
        let hash_input = [
            Fp::from(input),
            Fp::from(input),
            Fp::from(input),
            Fp::from(input),
        ];

        const WIDTH: usize = 5;
        const RATE: usize = 4;
        const L: usize = 4;

        let digest =
            poseidon::Hash::<_, MySpec<WIDTH, RATE>, ConstantLength<L>, WIDTH, RATE>::init()
                .hash(hash_input);

        let circuit = PoseidonCircuit::<MySpec<WIDTH, RATE>, WIDTH, RATE, L> {
            hash_input: hash_input.map(|x| Value::known(x)),
            digest: Value::known(digest),
            _spec: PhantomData,
        };

        halo2_proofs::dev::CircuitLayout::default()
            .render(7, &circuit, &root)
            .unwrap();
    }
}
