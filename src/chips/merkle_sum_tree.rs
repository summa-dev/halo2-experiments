use super::poseidon::{PoseidonChip, PoseidonConfig};
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation, halo2curves::pasta::Fp};
use halo2_gadgets::poseidon::primitives::P128Pow5T3;

#[derive(Debug, Clone)]
pub struct MerkleSumTreeConfig {
    pub advice: [Column<Advice>; 6],
    pub bool_selector: Selector,
    pub swap_selector: Selector,
    pub sum_selector: Selector,
    pub instance: Column<Instance>,
    pub poseidon_config: PoseidonConfig<3, 2, 4>,
}
#[derive(Debug, Clone)]
pub struct MerkleSumTreeChip {
    config: MerkleSumTreeConfig
}

impl MerkleSumTreeChip {
    pub fn construct(config: MerkleSumTreeConfig) -> Self {
        Self {
            config
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        advice: [Column<Advice>; 6],
        instance: Column<Instance>,
    ) -> MerkleSumTreeConfig {
        let col_a = advice[0];
        let col_b = advice[1];
        let col_c = advice[2];
        let col_d = advice[3];
        let col_e = advice[4];
        let col_f = advice[5];

        // create selectors 
        let bool_selector = meta.selector();
        let swap_selector = meta.selector();
        let sum_selector = meta.selector();

        meta.enable_equality(col_a); // enable equality for leaf_hash copy constraint with instance column
        meta.enable_equality(col_b); // enable equality for balance_hash copy constraint with instance column

        meta.enable_equality(col_e); // enable equality for computed_hash copy constraint across regions and for copy constraint with instance column
        meta.enable_equality(col_f); // enable equality for computed_sum copy constraint across regions and for copy constraint with instance column

        meta.enable_equality(instance);

        // Enforces that c is either a 0 or 1 when the bool selector is enabled
        // s * c * (1 - c) = 0
        meta.create_gate("bool constraint", |meta| {
            let s = meta.query_selector(bool_selector);
            let c = meta.query_advice(col_c, Rotation::cur());
            vec![s * c.clone() * (Expression::Constant(Fp::from(1)) - c)]
        });

        // TO DO: Modify swap constraint to work with 4 inputs. Similar to circom mux4.
        // Enforces that if the swap bit (c) is on, l=b and r=a. Otherwise, l=a and r=b.
        // s * (c * 2 * (b - a) - (l - a) - (b - r)) = 0
        // This applies only when the swap selector is enabled
        meta.create_gate("swap constraint", |meta| {
            let s = meta.query_selector(swap_selector);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            let l = meta.query_advice(col_a, Rotation::next());
            let r = meta.query_advice(col_b, Rotation::next());
            vec![
                s * (c * Expression::Constant(Fp::from(2)) * (b.clone() - a.clone())
                    - (l - a)
                    - (b - r)),
            ]
        });

        // Enforces that input_left_balance + input_right_balance = computed_sum
        meta.create_gate("sum constraint", |meta| {
            let s = meta.query_selector(sum_selector);
            let left_balance = meta.query_advice(col_b, Rotation::cur());
            let right_balance = meta.query_advice(col_d, Rotation::cur());
            let computed_sum = meta.query_advice(col_f, Rotation::cur());
            vec![s * (left_balance + right_balance - computed_sum)]
        });

        // TO DO: Understand if this is intantiated correctly
        let hash_inputs = (0..3).map(|_| meta.advice_column()).collect::<Vec<_>>();

        // TO DO: Understand the role of the instance in the poseidon_config
        let poseidon_config = PoseidonChip::<P128Pow5T3, 3, 2, 4>::configure(meta, hash_inputs, instance);

        MerkleSumTreeConfig {
            advice: [col_a, col_b, col_c, col_d, col_e, col_f],
            bool_selector,
            swap_selector,
            sum_selector,
            instance,
            poseidon_config
        }
    }

    pub fn assing_leaf_hash_and_balance(
        &self,
        mut layouter: impl Layouter<Fp>,
        leaf_hash: Value<Fp>,
        leaf_balance: Value<Fp>
    ) -> Result<(AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>), Error> {
        let leaf_hash_cell = layouter.assign_region(
            || "assign leaf hash",
            |mut region| region.assign_advice(|| "leaf hash", self.config.advice[0], 0, || leaf_hash),
        )?;

        let leaf_balance_cell  = layouter.assign_region(
            || "assign leaf balance",
            |mut region| region.assign_advice(|| "assign leaf", self.config.advice[0], 0, || leaf_balance),
        )?;

        Ok((leaf_hash_cell, leaf_balance_cell))
    }

    pub fn merkle_prove_layer(
        &self,
        mut layouter: impl Layouter<Fp>,
        prev_hash_cell: &AssignedCell<Fp, Fp>,
        prev_balance_cell: &AssignedCell<Fp, Fp>,
        element_hash: Value<Fp>,
        element_balance: Value<Fp>,
        index: Value<Fp>,
    ) -> Result<(AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>), Error> {

        let (left_hash, left_balance, right_hash, right_balance) = layouter.assign_region(
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
                // TO DO Fix the swap constraint to work with 4 inputs and return 4 outputs
                self.config.sum_selector.enable(&mut region, 1)?;
                // Here we just perform the assignment - no hashing is performed here!
                let node_cell_value = node_cell.value().map(|x| x.to_owned());
                let (mut l, mut r) = (node_cell_value, path_element);
                index.map(|x| {
                    (l, r) = if x == Fp::zero() { (l, r) } else { (r, l) };
                });

                // We need to perform the assignment of the row below
                let left_hash = region.assign_advice(
                    || "assign left hash to be hashed",
                    self.config.advice[0],
                    1,
                    || l,
                )?;

                let left_balance = region.assign_advice(
                    || "assign left balance to be hashed",
                    self.config.advice[1],
                    1,
                    || l,
                )?;

                let right_hash = region.assign_advice(
                    || "assign right hash to be hashed",
                    self.config.advice[2],
                    1,
                    || r,
                )?;

                let right_balance = region.assign_advice(
                    || "assign right balance to be hashed",
                    self.config.advice[3],
                    1,
                    || r,
                )?;

                Ok((left_hash, left_balance, right_hash, right_balance))
            },
        )?;

        // instantiate the poseidon_chip
        let poseidon_chip = PoseidonChip::<P128Pow5T3, 3, 2, 4>::construct(self.config.poseidon_config.clone());

        // The hash function inside the poseidon_chip performs the following action
        // 1. Copy the left and right cells from the previous row
        // 2. Perform the hash function and assign the digest to the current row
        // 3. Constrain the digest to be equal to the hash of the left and right values
        let computed_hash = poseidon_chip.hash(layouter.namespace(|| "hash two child nodes"), &[left_hash, left_balance, right_hash, right_balance])?;
        // TO DO: modify computed_sum variable
        let computed_sum = poseidon_chip.hash(layouter.namespace(|| "hash two child nodes"), &[left_hash, left_balance, right_hash, right_balance])?;
        Ok((computed_hash, computed_sum))
    }

    // Enforce permutation check between input cell and instance column at row passed as input
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        cell: &AssignedCell<Fp, Fp>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}
