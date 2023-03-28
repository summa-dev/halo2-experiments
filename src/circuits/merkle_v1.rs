use super::super::chips::merkle_v1::{MerkleTreeV1Chip, MerkleTreeV1Config};

use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*};

#[derive(Default)]
struct MerkleTreeV1Circuit<F> {
    pub leaf: Value<F>,
    pub path_elements: Vec<Value<F>>,
    pub path_indices: Vec<Value<F>>,
}

impl<F: FieldExt> Circuit<F> for MerkleTreeV1Circuit<F> {
    type Config = MerkleTreeV1Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let bool_selector = meta.selector();
        let swap_selector = meta.selector();
        let hash_selector = meta.selector();
        let instance = meta.instance_column();

        MerkleTreeV1Chip::configure(
            meta,
            [col_a, col_b, col_c],
            bool_selector,
            swap_selector,
            hash_selector,
            instance,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // We create a new instance of chip using the config passed as input
        let chip = MerkleTreeV1Chip::<F>::construct(config);

        let leaf_cell = chip.assing_leaf(layouter.namespace(|| "load leaf"), self.leaf)?;

        // Verify that the leaf matches the public input
        chip.expose_public(layouter.namespace(|| "leaf"), &leaf_cell, 0)?;

        // apply it for level 0 of the merkle tree
        let mut digest = chip.merkle_prove_layer(
            layouter.namespace(|| "level 0"),
            &leaf_cell,
            self.path_elements[0],
            self.path_indices[0],
        )?;

        // apply it for the remaining levels of the merkle tree
        for i in 1..self.path_elements.len() {
            digest = chip.merkle_prove_layer(
                layouter.namespace(|| "next level"),
                &digest,
                self.path_elements[i],
                self.path_indices[i],
            )?;
        }

        chip.expose_public(layouter.namespace(|| "root"), &digest, 1)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MerkleTreeV1Circuit;
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};

    #[test]
    fn test_merkle_tree_1() {
        let leaf = 99u64;
        let elements = vec![1u64, 5u64, 6u64, 9u64, 9u64];
        let indices = vec![0u64, 0u64, 0u64, 0u64, 0u64];
        let digest: u64 = leaf + elements.iter().sum::<u64>();

        let leaf_fp = Value::known(Fp::from(leaf));
        let elements_fp: Vec<Value<Fp>> = elements
            .iter()
            .map(|x| Value::known(Fp::from(x.to_owned())))
            .collect();
        let indices_fp: Vec<Value<Fp>> = indices
            .iter()
            .map(|x| Value::known(Fp::from(x.to_owned())))
            .collect();

        let circuit = MerkleTreeV1Circuit {
            leaf: leaf_fp,
            path_elements: elements_fp,
            path_indices: indices_fp,
        };

        let public_input = vec![Fp::from(leaf), Fp::from(digest)];
        let prover = MockProver::run(10, &circuit, vec![public_input]).unwrap();
        prover.assert_satisfied();
    }
}

#[cfg(feature = "dev-graph")]
#[test]
fn print_merkle_tree_1() {
    use halo2_proofs::halo2curves::pasta::Fp;
    use plotters::prelude::*;

    let root =
        BitMapBackend::new("prints/merkle-tree-1-layout.png", (1024, 3096)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root
        .titled("Merkle Tree 1 Layout", ("sans-serif", 60))
        .unwrap();

    let leaf = 99u64;
    let elements = vec![1u64, 5u64, 6u64, 9u64, 9u64];
    let indices = vec![0u64, 0u64, 0u64, 0u64, 0u64];
    let digest: u64 = leaf + elements.iter().sum::<u64>();

    let leaf_fp = Value::known(Fp::from(leaf));
    let elements_fp: Vec<Value<Fp>> = elements
        .iter()
        .map(|x| Value::known(Fp::from(x.to_owned())))
        .collect();
    let indices_fp: Vec<Value<Fp>> = indices
        .iter()
        .map(|x| Value::known(Fp::from(x.to_owned())))
        .collect();

    let circuit = MerkleTreeV1Circuit {
        leaf: leaf_fp,
        path_elements: elements_fp,
        path_indices: indices_fp,
    };

    halo2_proofs::dev::CircuitLayout::default()
        .render(4, &circuit, &root)
        .unwrap();
}
