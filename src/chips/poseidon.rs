/*
An easy-to-use implementation of the Poseidon Hash in the form of a Halo2 Chip. While the Poseidon Hash function
is already implemented in halo2_gadgets, there is no wrapper chip that makes it easy to use in other circuits.
*/

// This chip adds a set of advice columns to the gadget Chip to store the inputs of the hash
// Furthermore it adds an instance column to store the public expected output of the hash

use halo2_gadgets::poseidon::{primitives::*, Hash, Pow5Chip, Pow5Config};
use halo2_proofs::{circuit::*, plonk::*, halo2curves::pasta::Fp};
use std::marker::PhantomData;

#[derive(Debug, Clone)]

// ?? Is this true for the L ??
// WIDTH, RATE and L are const generics for the struct, which represent the width, rate, and number of rounds of the Poseidon hash function, respectively.
// This means they are values that are known at compile time and can be used to specialize the implementation of the struct.
// The actual chip provided by halo2_gadgets is added to the parent Chip.
pub struct PoseidonConfig<const WIDTH: usize, const RATE: usize, const L: usize> {
    inputs: Vec<Column<Advice>>,
    instance: Column<Instance>,
    pow5_config: Pow5Config<Fp, WIDTH, RATE>,
}

#[derive(Debug, Clone)]

pub struct PoseidonChip<
    S: Spec<Fp, WIDTH, RATE>,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize,
> {
    config: PoseidonConfig<WIDTH, RATE, L>,
    _marker: PhantomData<S>,
}

impl<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize>
    PoseidonChip<S, WIDTH, RATE, L>
{
    pub fn construct(config: PoseidonConfig<WIDTH, RATE, L>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    // Configuration of the PoseidonChip
    // ?? Modify it = pass the columns to the configure function! ??
    // ?? Do I need to impose copy constraint between inputs and state vectors?
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> PoseidonConfig<WIDTH, RATE, L> {
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let instance = meta.instance_column();
        for i in 0..WIDTH {
            meta.enable_equality(state[i]);
        }
        meta.enable_equality(instance);
        meta.enable_constant(rc_b[0]);

        let pow5_config = Pow5Chip::configure::<S>(
            meta,
            state.clone().try_into().unwrap(),
            partial_sbox.try_into().unwrap(),
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        PoseidonConfig {
            inputs: state.clone().try_into().unwrap(),
            instance,
            pow5_config: pow5_config,
        }
    }

    // L is the number of inputs to the hash function
    // Assign the inputs to the advice colums
    pub fn load_private_inputs(
        &self,
        mut layouter: impl Layouter<Fp>,
        inputs: [Value<Fp>; L],
    ) -> Result<[AssignedCell<Fp, Fp>; L], Error> {
        layouter.assign_region(
            || "load private inputs",
            |mut region| -> Result<[AssignedCell<Fp, Fp>; L], Error> {
                let result = inputs
                    .iter()
                    .enumerate()
                    .map(|(i, x)| {
                        region.assign_advice(
                            || "private input",
                            self.config.inputs[i],
                            0,
                            || x.to_owned(),
                        )
                    })
                    .collect::<Result<Vec<AssignedCell<Fp, Fp>>, Error>>();
                Ok(result?.try_into().unwrap())
            },
        )
    }

    // L is the number of inputs to the hash function
    // Takes the cells containing the input values of the hash function and return the cell containing the hash output
    // It uses the pow5_chip to compute the hash
    pub fn hash(
        &self,
        mut layouter: impl Layouter<Fp>,
        words: &[AssignedCell<Fp, Fp>; L],
    ) -> Result<AssignedCell<Fp, Fp>, Error> {

        let pow5_chip = Pow5Chip::construct(self.config.pow5_config.clone());
        
        // Assign values to word_cells by copying it from the cells passed as input
        let word_cells = layouter.assign_region(
            || "load words",
            |mut region| -> Result<[AssignedCell<Fp, Fp>; L], Error> {
                let result = words
                    .iter()
                    .enumerate()
                    .map(|(i, word)| {
                        word.copy_advice(
                            || format!("word {}", i),
                            &mut region,
                            self.config.inputs[i],
                            0,
                        )
                    })
                    .collect::<Result<Vec<AssignedCell<Fp, Fp>>, Error>>();
                Ok(result?.try_into().unwrap())
            },
        )?;

        // initialize the hasher
        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            pow5_chip,
            layouter.namespace(|| "hasher"),
        )?;
        hasher.hash(layouter.namespace(|| "hash"), word_cells)
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        cell: &AssignedCell<Fp, Fp>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}