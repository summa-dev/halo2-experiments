use super::super::chips::merkle_v3::{MerkleTreeV3Chip, MerkleTreeV3Config};
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, halo2curves::pasta::Fp};

#[derive(Default)]
struct MerkleTreeV3Circuit {
    pub leaf: Value<Fp>,
    pub path_elements: Vec<Value<Fp>>,
    pub path_indices: Vec<Value<Fp>>,
}

impl Circuit<Fp> for MerkleTreeV3Circuit {

    type Config = MerkleTreeV3Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {

        // config for the merkle tree chip
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let bool_selector = meta.selector();
        let swap_selector = meta.selector();
        let instance = meta.instance_column();


        MerkleTreeV3Chip::configure(
            meta,
            [col_a, col_b, col_c],
            bool_selector,
            swap_selector,
            instance,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = MerkleTreeV3Chip::construct(config);
        let leaf_cell = chip.assing_leaf(layouter.namespace(|| "assign leaf"), self.leaf)?;
        chip.expose_public(layouter.namespace(|| "public leaf"), &leaf_cell, 0)?;

        // apply it for level 0 of the merkle tree
        // node cell passed as input is the leaf cell
        let mut digest = chip.merkle_prove_layer(
            layouter.namespace(|| "merkle_prove"),
            &leaf_cell,
            self.path_elements[0],
            self.path_indices[0],
        )?;

        // apply it for the remaining levels of the merkle tree
        // node cell passed as input is the digest cell
        for i in 1..self.path_elements.len() {
            digest = chip.merkle_prove_layer(
                layouter.namespace(|| "next level"),
                &digest,
                self.path_elements[i],
                self.path_indices[i],
            )?;
        }
        chip.expose_public(layouter.namespace(|| "public root"), &digest, 1)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MerkleTreeV3Circuit;
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};
    use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength, P128Pow5T3};

    fn compute_merkle_root(leaf: &u64, elements: &Vec<u64>, indices: &Vec<u64>) -> Fp {
        let k = elements.len();
        let mut digest = Fp::from(leaf.clone());
        let mut message: [Fp; 2];
        for i in 0..k {
            if indices[i] == 0 {
                message = [digest, Fp::from(elements[i])];
            } else {
                message = [Fp::from(elements[i]), digest];
            }

            digest = poseidon::Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init()
                .hash(message);
        }
        return digest;
    }

    #[test]
    fn test_merkle_tree_3() {
        let leaf = 99u64;
        let elements = vec![1u64, 5u64, 6u64, 9u64, 9u64];
        let indices = vec![0u64, 0u64, 0u64, 0u64, 0u64];

        // print leaf
        println!("leaf: {}", leaf);

        let root = compute_merkle_root(&leaf, &elements, &indices);

        let leaf_fp = Value::known(Fp::from(leaf));
        let elements_fp: Vec<Value<Fp>> = elements
            .iter()
            .map(|x| Value::known(Fp::from(x.to_owned())))
            .collect();
        let indices_fp: Vec<Value<Fp>> = indices
            .iter()
            .map(|x| Value::known(Fp::from(x.to_owned())))
            .collect();

        let circuit = MerkleTreeV3Circuit {
            leaf: leaf_fp,
            path_elements: elements_fp,
            path_indices: indices_fp,
        };

        let correct_public_input = vec![Fp::from(leaf), root];
        let valid_prover = MockProver::run(10, &circuit, vec![correct_public_input]).unwrap();
        valid_prover.assert_satisfied();

        let wrong_public_input = vec![Fp::from(leaf), Fp::from(0)];
        let invalid_prover = MockProver::run(10, &circuit, vec![wrong_public_input]).unwrap();
        assert!(invalid_prover.verify().is_err());

    }
}

#[cfg(feature = "dev-graph")]
#[test]
fn print_merkle_tree_2() {
    use halo2_proofs::halo2curves::pasta::Fp;
    use plotters::prelude::*;

    let root =
        BitMapBackend::new("prints/merkle-tree-2-layout.png", (1024, 3096)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root
        .titled("Merkle Tree 2 Layout", ("sans-serif", 60))
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

    let circuit = MerkleTreeV2Circuit {
        leaf: leaf_fp,
        path_elements: elements_fp,
        path_indices: indices_fp,
    };

    halo2_proofs::dev::CircuitLayout::default()
        .render(4, &circuit, &root)
        .unwrap();
}