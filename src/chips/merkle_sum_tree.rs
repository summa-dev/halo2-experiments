use super::poseidon::hash::{PoseidonChip, PoseidonConfig};
use super::poseidon::spec::MySpec;
use halo2_proofs::{arithmetic::FieldExt, circuit::*,plonk::*, poly::Rotation};

const WIDTH: usize = 5;
const RATE: usize = 4;
const L: usize = 4;

#[derive(Debug, Clone)]
pub struct MerkleSumTreeConfig <F: FieldExt> {
    pub advice: [Column<Advice>; 5],
    pub bool_selector: Selector,
    pub swap_selector: Selector,
    pub sum_selector: Selector,
    pub instance: Column<Instance>,
    pub poseidon_config: PoseidonConfig<F, WIDTH, RATE, L>,
}
#[derive(Debug, Clone)]
pub struct MerkleSumTreeChip <F: FieldExt>{
    config: MerkleSumTreeConfig<F>,
}

impl <F: FieldExt> MerkleSumTreeChip<F> {
    pub fn construct(config: MerkleSumTreeConfig<F>) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 5],
        instance: Column<Instance>,
    ) -> MerkleSumTreeConfig<F> {
        let col_a = advice[0];
        let col_b = advice[1];
        let col_c = advice[2];
        let col_d = advice[3];
        let col_e = advice[4];

        // create selectors
        let bool_selector = meta.selector();
        let swap_selector = meta.selector();
        let sum_selector = meta.selector();

        // enable equality for leaf_hash copy constraint with instance column (col_a)
        // enable equality for balance_hash copy constraint with instance column (col_b)
        // enable equality for copying left_hash, left_balance, right_hash, right_balance into poseidon_chip (col_a, col_b, col_c, col_d)
        // enable equality for computed_sum copy constraint with instance column (col_e)
        meta.enable_equality(col_a);
        meta.enable_equality(col_b);
        meta.enable_equality(col_c); 
        meta.enable_equality(col_d);
        meta.enable_equality(col_e);
        meta.enable_equality(instance);

        // Enforces that e is either a 0 or 1 when the bool selector is enabled
        // s * e * (1 - e) = 0
        meta.create_gate("bool constraint", |meta| {
            let s = meta.query_selector(bool_selector);
            let e = meta.query_advice(col_e, Rotation::cur());
            vec![s * e.clone() * (Expression::Constant(F::from(1)) - e)]
        });

        // Enforces that if the swap bit (e) is on, l1=c, l2=d, r1=a, and r2=b. Otherwise, l1=a, l2=b, r1=c, and r2=d.
        // This applies only when the swap selector is enabled
        meta.create_gate("swap constraint", |meta| {
            let s = meta.query_selector(swap_selector);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            let d = meta.query_advice(col_d, Rotation::cur());
            let e = meta.query_advice(col_e, Rotation::cur());
            let l1 = meta.query_advice(col_a, Rotation::next());
            let l2 = meta.query_advice(col_b, Rotation::next());
            let r1 = meta.query_advice(col_c, Rotation::next());
            let r2 = meta.query_advice(col_d, Rotation::next());

            vec![
                s.clone() * (e.clone() * Expression::Constant(F::from(2)) * (c.clone() - a.clone())
                    - (l1 - a)
                    - (c - r1)),
                s * (e * Expression::Constant(F::from(2)) * (d.clone() - b.clone())
                    - (l2 - b)
                    - (d - r2)),
            ]
        });

        // Enforces that input_left_balance + input_right_balance = computed_sum
        meta.create_gate("sum constraint", |meta| {
            let s = meta.query_selector(sum_selector);
            let left_balance = meta.query_advice(col_b, Rotation::cur());
            let right_balance = meta.query_advice(col_d, Rotation::cur());
            let computed_sum = meta.query_advice(col_e, Rotation::cur());
            vec![s * (left_balance + right_balance - computed_sum)]
        });

        // TO DO: Understand if this is intantiated correctly
        let hash_inputs = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();

        let poseidon_config = PoseidonChip::<F, MySpec<F, WIDTH, RATE>, WIDTH, RATE, L>::configure(
            meta,
            hash_inputs
        );

        MerkleSumTreeConfig {
            advice: [col_a, col_b, col_c, col_d, col_e],
            bool_selector,
            swap_selector,
            sum_selector,
            instance,
            poseidon_config,
        }
    }

    pub fn assing_leaf_hash_and_balance(
        &self,
        mut layouter: impl Layouter<F>,
        leaf_hash: Value<F>,
        leaf_balance: Value<F>,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
        let leaf_hash_cell = layouter.assign_region(
            || "assign leaf hash",
            |mut region| {
                region.assign_advice(|| "leaf hash", self.config.advice[0], 0, || leaf_hash)
            },
        )?;

        let leaf_balance_cell = layouter.assign_region(
            || "assign leaf balance",
            |mut region| {
                region.assign_advice(|| "leaf balance", self.config.advice[1], 0, || leaf_balance)
            },
        )?;

        Ok((leaf_hash_cell, leaf_balance_cell))
    }

    pub fn merkle_prove_layer(
        &self,
        mut layouter: impl Layouter<F>,
        prev_hash_cell: &AssignedCell<F, F>,
        prev_balance_cell: &AssignedCell<F, F>,
        element_hash: Value<F>,
        element_balance: Value<F>,
        index: Value<F>,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
        let (left_hash, left_balance, right_hash, right_balance, computed_sum_cell) = layouter
            .assign_region(
                || "merkle prove layer",
                |mut region| {
                    // Row 0 
                    self.config.bool_selector.enable(&mut region, 0)?;
                    self.config.swap_selector.enable(&mut region, 0)?;
                    prev_hash_cell.copy_advice(
                        || "copy hash cell from previous level",
                        &mut region,
                        self.config.advice[0],
                        0,
                    )?;
                    prev_balance_cell.copy_advice(
                        || "copy balance cell from previous level",
                        &mut region,
                        self.config.advice[1],
                        0,
                    )?;
                    region.assign_advice(
                        || "assign element_hash",
                        self.config.advice[2],
                        0,
                        || element_hash,
                    )?;
                    region.assign_advice(
                        || "assign balance",
                        self.config.advice[3],
                        0,
                        || element_balance,
                    )?;
                    region.assign_advice(|| 
                        "assign index", 
                    self.config.advice[4], 
                    0, 
                    || index
                    )?;

                    // Row 1
                    self.config.sum_selector.enable(&mut region, 1)?;

                    let prev_hash_cell_value = prev_hash_cell.value().map(|x| x.to_owned());
                    let prev_balance_cell_value = prev_balance_cell.value().map(|x| x.to_owned());

                    // perform the swap according to the index
                    let (mut l1, mut l2, mut r1, mut r2) = (
                        prev_hash_cell_value,
                        prev_balance_cell_value,
                        element_hash,
                        element_balance,
                    );
                    index.map(|x| {
                        (l1, l2, r1, r2) = if x == F::zero() {
                            (l1, l2, r1, r2)
                        } else {
                            (r1, r2, l1, l2)
                        };
                    });

                    // We need to perform the assignment of the row below
                    let left_hash = region.assign_advice(
                        || "assign left hash to be hashed",
                        self.config.advice[0],
                        1,
                        || l1,
                    )?;

                    let left_balance = region.assign_advice(
                        || "assign left balance to be hashed",
                        self.config.advice[1],
                        1,
                        || l2,
                    )?;

                    let right_hash = region.assign_advice(
                        || "assign right hash to be hashed",
                        self.config.advice[2],
                        1,
                        || r1,
                    )?;

                    let right_balance = region.assign_advice(
                        || "assign right balance to be hashed",
                        self.config.advice[3],
                        1,
                        || r2,
                    )?;

                    let computed_sum = left_balance.value().zip(right_balance.value()).map(|(a, b)| *a + b);

                    // Now we can assign the sum result to the computed_sum cell.
                    // TO DO: is it constrained correctly?
                    let computed_sum_cell = region.assign_advice(
                        || "assign sum of left and right balance",
                        self.config.advice[4],
                        1,
                        || computed_sum,
                    )?;

                    Ok((
                        left_hash,
                        left_balance,
                        right_hash,
                        right_balance,
                        computed_sum_cell,
                    ))
                },
            )?;

        // instantiate the poseidon_chip
        let poseidon_chip = PoseidonChip::<F, MySpec<F, WIDTH, RATE>, WIDTH, RATE, L>::construct(
            self.config.poseidon_config.clone(),
        );

        // The hash function inside the poseidon_chip performs the following action
        // 1. Copy the left and right cells from the previous row
        // 2. Perform the hash function and assign the digest to the current row
        // 3. Constrain the digest to be equal to the hash of the left and right values
        let computed_hash = poseidon_chip.hash(
            layouter.namespace(|| "hash four child nodes"),
            &[left_hash, left_balance, right_hash, right_balance],
        )?;

        Ok((computed_hash, computed_sum_cell))
    }

    // Enforce permutation check between input cell and instance column at row passed as input
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        cell: &AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}
