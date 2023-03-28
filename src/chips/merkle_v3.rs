use super::poseidon::{PoseidonChip, PoseidonConfig};
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation, halo2curves::pasta::Fp};
use halo2_gadgets::poseidon::primitives::P128Pow5T3;

#[derive(Debug, Clone)]
pub struct MerkleTreeV3Config {
    pub advice: [Column<Advice>; 3],
    pub bool_selector: Selector,
    pub swap_selector: Selector,
    pub instance: Column<Instance>,
    pub poseidon_config: PoseidonConfig<3, 2, 2>,
}
#[derive(Debug, Clone)]
pub struct MerkleTreeV3Chip {
    config: MerkleTreeV3Config
}

impl MerkleTreeV3Chip {
    pub fn construct(config: MerkleTreeV3Config) -> Self {
        Self {
            config
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        advice: [Column<Advice>; 3],
        instance: Column<Instance>,
    ) -> MerkleTreeV3Config {
        let col_a = advice[0];
        let col_b = advice[1];
        let col_c = advice[2];

        // create selectors 
        let bool_selector = meta.selector();
        let swap_selector = meta.selector();

        meta.enable_equality(col_a);
        meta.enable_equality(col_b);
        meta.enable_equality(col_c);
        meta.enable_equality(instance);

        // Enforces that c is either a 0 or 1 when the bool selector is enabled
        // s * c * (1 - c) = 0
        meta.create_gate("bool constraint", |meta| {
            let s = meta.query_selector(bool_selector);
            let c = meta.query_advice(col_c, Rotation::cur());
            vec![s * c.clone() * (Expression::Constant(Fp::from(1)) - c)]
        });

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


        let hash_inputs = (0..3).map(|_| meta.advice_column()).collect::<Vec<_>>();

        let poseidon_config = PoseidonChip::<P128Pow5T3, 3, 2, 2>::configure(meta, hash_inputs, instance);

        MerkleTreeV3Config {
            advice: [col_a, col_b, col_c],
            bool_selector,
            swap_selector,
            instance,
            poseidon_config
        }
    }

    pub fn assing_leaf(
        &self,
        mut layouter: impl Layouter<Fp>,
        leaf: Value<Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let node_cell = layouter.assign_region(
            || "assign leaf",
            |mut region| region.assign_advice(|| "assign leaf", self.config.advice[0], 0, || leaf),
        )?;

        Ok(node_cell)
    }

    pub fn merkle_prove_layer(
        &self,
        mut layouter: impl Layouter<Fp>,
        node_cell: &AssignedCell<Fp, Fp>,
        path_element: Value<Fp>,
        index: Value<Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let (left, right) = layouter.assign_region(
            || "merkle prove layer",
            |mut region| {
                // Row 0
                self.config.bool_selector.enable(&mut region, 0)?;
                self.config.swap_selector.enable(&mut region, 0)?;
                node_cell.copy_advice(
                    || "copy node cell from previous prove layer",
                    &mut region,
                    self.config.advice[0],
                    0,
                )?;
                region.assign_advice(
                    || "assign element",
                    self.config.advice[1],
                    0,
                    || path_element,
                )?;
                region.assign_advice(|| 
                    "assign index", 
                    self.config.advice[2], 
                    0, 
                    || index
                )?;

                // Row 1
                // Here we just perform the assignment - no hashing is performed here!
                let node_cell_value = node_cell.value().map(|x| x.to_owned());
                let (mut l, mut r) = (node_cell_value, path_element);
                index.map(|x| {
                    (l, r) = if x == Fp::zero() { (l, r) } else { (r, l) };
                });

                // We need to perform the assignment of the row below in order to perform the swap check
                let left = region.assign_advice(
                    || "assign left to be hashed",
                    self.config.advice[0],
                    1,
                    || l,
                )?;
                let right = region.assign_advice(
                    || "assign right to be hashed",
                    self.config.advice[1],
                    1,
                    || r,
                )?;

                Ok((left, right))
            },
        )?;

        // instantiate the poseidon_chip
        let poseidon_chip = PoseidonChip::<P128Pow5T3, 3, 2, 2>::construct(self.config.poseidon_config.clone());

        // The hash function inside the poseidon_chip performs the following action
        // 1. Copy the left and right cells from the previous row
        // 2. Perform the hash function and assign the digest to the current row
        // 3. Constrain the digest to be equal to the hash of the left and right values
        let digest = poseidon_chip.hash(layouter.namespace(|| "hash row constaint"), &[left, right])?;
        Ok(digest)
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
