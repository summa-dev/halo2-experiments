/*
An easy-to-use implementation of the Poseidon Hash in the form of a Halo2 Chip. While the Poseidon Hash function
is already implemented in halo2_gadgets, there is no wrapper chip that makes it easy to use in other circuits.
*/

// This chip adds a set of advice columns to the gadget Chip to store the inputs of the hash
// Furthermore it adds an instance column to store the public expected output of the hash

use halo2_gadgets::poseidon::{primitives::*, Hash, Pow5Chip, Pow5Config};
use halo2_proofs::{circuit::*, plonk::*, arithmetic::FieldExt};
use std::marker::PhantomData;

#[derive(Debug, Clone)]

// WIDTH, RATE and L are const generics for the struct, which represent the width, rate, and number of inputs for the Poseidon hash function, respectively.
// This means they are values that are known at compile time and can be used to specialize the implementation of the struct.
// The actual chip provided by halo2_gadgets is added to the parent Chip.
pub struct PoseidonConfig<F: FieldExt, const WIDTH: usize, const RATE: usize, const L: usize> {
    hash_inputs: Vec<Column<Advice>>,
    instance: Column<Instance>,
    pow5_config: Pow5Config<F, WIDTH, RATE>,
}

#[derive(Debug, Clone)]

pub struct PoseidonChip<
    F: FieldExt,
    S: Spec<F, WIDTH, RATE>,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize,
> {
    config: PoseidonConfig<F, WIDTH, RATE, L>,
    _marker: PhantomData<S>,
}

impl<F: FieldExt, S: Spec<F, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize>
    PoseidonChip<F, S, WIDTH, RATE, L>
{
    pub fn construct(config: PoseidonConfig<F, WIDTH, RATE, L>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    // Configuration of the PoseidonChip
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        state: Vec<Column<Advice>>,
        partial_sbox: Column<Advice>,
        rc_a: Vec<Column<Fixed>>,
        rc_b: Vec<Column<Fixed>>,
        instance: Column<Instance>
    ) -> PoseidonConfig<F, WIDTH, RATE, L> {
        
        for i in 0..WIDTH {
            meta.enable_equality(state[i]);
        }
        meta.enable_equality(instance);
        meta.enable_constant(rc_b[0]);

        let pow5_config = Pow5Chip::configure::<S>(
            meta,
            state.clone().try_into().unwrap(),
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        PoseidonConfig {
            hash_inputs: state.clone().try_into().unwrap(),
            instance,
            pow5_config,
        }
    }

    // L is the number of inputs to the hash function
    // Takes the cells containing the input values of the hash function and return the cell containing the hash output
    // It uses the pow5_chip to compute the hash
    pub fn hash(
        &self,
        mut layouter: impl Layouter<F>,
        inputs: [Value<F>; L],
    ) -> Result<AssignedCell<F, F>, Error> {
        
        // Assign values to word_cells by copying it from the cells passed as input
        let hash_input_cells = layouter.assign_region(
            || "load private inputs",
            |mut region| -> Result<[AssignedCell<F, F>; L], Error> {
                let result = inputs
                    .iter()
                    .enumerate()
                    .map(|(i, x)| {
                        region.assign_advice(
                            || "private input",
                            self.config.hash_inputs[i],
                            0,
                            || x.to_owned(),
                        )
                    })
                    .collect::<Result<Vec<AssignedCell<F, F>>, Error>>();
                Ok(result?.try_into().unwrap())
            },
        )?;

        let pow5_chip = Pow5Chip::construct(self.config.pow5_config.clone());

        // initialize the hasher
        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            pow5_chip,
            layouter.namespace(|| "hasher"),
        )?;
        hasher.hash(layouter.namespace(|| "hash"), hash_input_cells)
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        cell: &AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}