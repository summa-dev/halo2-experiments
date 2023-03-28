use super::hash_v2::{Hash2Chip, Hash2Config};
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct MerkleTreeV2Config {
    pub advice: [Column<Advice>; 3],
    pub bool_selector: Selector,
    pub swap_selector: Selector,
    pub hash_selector: Selector,
    pub instance: Column<Instance>,
    pub hash2_config: Hash2Config,
}

pub struct MerkleTreeV2Chip<F: FieldExt> {
    config: MerkleTreeV2Config,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> MerkleTreeV2Chip<F> {
    pub fn construct(config: MerkleTreeV2Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 3],
        bool_selector: Selector,
        swap_selector: Selector,
        hash_selector: Selector,
        instance: Column<Instance>,
    ) -> MerkleTreeV2Config {
        let col_a = advice[0];
        let col_b = advice[1];
        let col_c = advice[2];

        // Enable equality on the advice column c and instance column to enable permutation check
        // between the last hash digest and the root hash passed inside the instance column
        meta.enable_equality(col_c);
        meta.enable_equality(instance);

        // Enable equality on the advice column a. This is need to carry digest from one level to the other
        // and perform copy_advice
        meta.enable_equality(col_a);

        // Enable equality on the advice column b. Need for permutation check when calling hash function
        meta.enable_equality(col_b);

        // Enforces that c is either a 0 or 1 when the bool selector is enabled
        // s * c * (1 - c) = 0
        meta.create_gate("bool constraint", |meta| {
            let s = meta.query_selector(bool_selector);
            let c = meta.query_advice(col_c, Rotation::cur());
            vec![s * c.clone() * (Expression::Constant(F::from(1)) - c)]
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
                s * (c * Expression::Constant(F::from(2)) * (b.clone() - a.clone())
                    - (l - a)
                    - (b - r)),
            ]
        });

        let hash2_config = Hash2Chip::configure(meta, advice, hash_selector, instance);

        MerkleTreeV2Config {
            advice: [col_a, col_b, col_c],
            bool_selector,
            swap_selector,
            hash_selector,
            instance,
            hash2_config,
        }
    }

    pub fn assing_leaf(
        &self,
        mut layouter: impl Layouter<F>,
        leaf: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let node_cell = layouter.assign_region(
            || "assign leaf",
            |mut region| region.assign_advice(|| "assign leaf", self.config.advice[0], 0, || leaf),
        )?;

        Ok(node_cell)
    }

    pub fn merkle_prove_layer(
        &self,
        mut layouter: impl Layouter<F>,
        node_cell: &AssignedCell<F, F>,
        path_element: Value<F>,
        index: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
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
                region.assign_advice(|| "assign index", self.config.advice[2], 0, || index)?;

                // Row 1
                // Here we just perform the assignment - no hashing is performed here!
                let node_cell_value = node_cell.value().map(|x| x.to_owned());
                let (mut l, mut r) = (node_cell_value, path_element);
                index.map(|x| {
                    (l, r) = if x == F::zero() { (l, r) } else { (r, l) };
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

        let hash_chip = Hash2Chip::construct(self.config.hash2_config.clone());

        // The hash function performs the following action
        // 1. Copy the left and right values from the previous row
        // 2. Perform the hash function and assign the digest to the current row
        // 3. Constrain the digest to be equal to the hash of the left and right values
        let digest = hash_chip.hash(layouter.namespace(|| "hash row constaint"), left, right)?;
        Ok(digest)
    }

    // Enforce permutation check between input cell and instance column
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        cell: &AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}
