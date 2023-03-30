use super::super::chips::merkle_sum_tree::{MerkleSumTreeChip, MerkleSumTreeConfig};
use halo2_proofs::{circuit::*, plonk::*, halo2curves::pasta::Fp};

#[derive(Default)]
struct MerkleSumTreeCircuit {
    pub leaf_hash: Value<Fp>,
    pub leaf_balance: Value<Fp>,
    pub path_element_hashes: Vec<Value<Fp>>,
    pub path_element_balances: Vec<Value<Fp>>,
    pub path_indices: Vec<Value<Fp>>,
}

impl Circuit<Fp> for MerkleSumTreeCircuit {

    type Config = MerkleSumTreeConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {

        // config columns for the merkle tree chip
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let col_d = meta.advice_column();
        let col_e = meta.advice_column();

        let instance = meta.instance_column();

        MerkleSumTreeChip::configure(
            meta,
            [col_a, col_b, col_c, col_d, col_e],
            instance,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {

        let chip = MerkleSumTreeChip::construct(config);
        let (leaf_hash_cell, leaf_balance_cell) = chip.assing_leaf_hash_and_balance(layouter.namespace(|| "assign leaf"), self.leaf_hash, self.leaf_balance)?;

        chip.expose_public(layouter.namespace(|| "public leaf hash"), &leaf_hash_cell, 0)?;
        chip.expose_public(layouter.namespace(|| "public leaf balance"), &leaf_balance_cell, 1)?;

        // apply it for level 0 of the merkle tree
        // node cells passed as inputs are the leaf_hash cell and the leaf_balance cell
        let (mut computed_hash_prev_level_cell, mut computed_balance_prev_level_cell) = chip.merkle_prove_layer(
            layouter.namespace(|| format!("level {} merkle proof", 0)),
            &leaf_hash_cell,
            &leaf_balance_cell,
            self.path_element_hashes[0],
            self.path_element_balances[0],
            self.path_indices[0],
        )?;

        // apply it for the remaining levels of the merkle tree
        // node cells passed as inputs are the computed_hash_prev_level cell and the computed_balance_prev_level cell
        for i in 1..self.path_element_balances.len() {
            (computed_hash_prev_level_cell, computed_balance_prev_level_cell) = chip.merkle_prove_layer(
                layouter.namespace(|| format!("level {} merkle proof", i)),
                &computed_hash_prev_level_cell,
                &computed_balance_prev_level_cell,
                self.path_element_hashes[i],
                self.path_element_balances[i],
                self.path_indices[i],
            )?;
        }

        chip.expose_public(layouter.namespace(|| "public root"), &computed_hash_prev_level_cell, 2)?;
        chip.expose_public(layouter.namespace(|| "public balance sum"), &computed_balance_prev_level_cell, 3)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MerkleSumTreeCircuit;
    use super::super::super::chips::poseidon::spec::MySpec;
    use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength};
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};

    const WIDTH: usize = 5;
    const RATE: usize = 4;
    const L: usize = 4;

    #[derive(Debug, Clone)]
    struct Node {
        hash: Fp,
        balance: Fp,
    }

    fn compute_merkle_sum_root(node: &Node,  elements: &Vec<Node>, indices: &Vec<u64>) -> Node {
        let k = elements.len();
        let mut digest = node.clone();
        let mut message: [Fp; 4];
        for i in 0..k {
            if indices[i] == 0 {
                message = [digest.hash, digest.balance, elements[i].hash, elements[i].balance];
            } else {
                message = [elements[i].hash, elements[i].balance, digest.hash, digest.balance];
            }

            digest.hash = poseidon::Hash::<_, MySpec<WIDTH, RATE>, ConstantLength<L>, WIDTH, RATE>::init()
                .hash(message);

            digest.balance = digest.balance + elements[i].balance;

        }
        digest
    }

    #[test]
    fn test_merkle_sum_tree() {
        let leaf = Node {
            hash: Fp::from(10u64),
            balance: Fp::from(100u64),
        };

        let elements = vec![
            Node {
                hash: Fp::from(1u64),
                balance: Fp::from(10u64),
            },
            Node {
                hash: Fp::from(5u64),
                balance: Fp::from(50u64),
            },
            Node {
                hash: Fp::from(6u64),
                balance: Fp::from(60u64),
            },
            Node {
                hash: Fp::from(9u64),
                balance: Fp::from(90u64),
            },
            Node {
                hash: Fp::from(9u64),
                balance: Fp::from(90u64),
            },
        ];

        let indices = vec![0u64, 0u64, 0u64, 0u64, 0u64];

        let root = compute_merkle_sum_root(&leaf, &elements, &indices);

        let element_hashes: Vec<Value<Fp>> = elements
            .iter()
            .map(|x| Value::known(x.hash))
            .collect();

        let element_balances: Vec<Value<Fp>> = elements
            .iter()
            .map(|x| Value::known(x.balance))
            .collect();

        let indices_fp: Vec<Value<Fp>> = indices
            .iter()
            .map(|x| Value::known(Fp::from(x.to_owned())))
            .collect();

        let circuit = MerkleSumTreeCircuit {
            leaf_hash: Value::known(leaf.hash),
            leaf_balance: Value::known(leaf.balance),
            path_element_hashes: element_hashes,
            path_element_balances: element_balances,
            path_indices: indices_fp,
        };

        let correct_public_input = vec![leaf.hash, leaf.balance, root.hash, Fp::from(400u64)];
        let valid_prover = MockProver::run(10, &circuit, vec![correct_public_input]).unwrap();
        valid_prover.assert_satisfied();

        let wrong_public_input = vec![leaf.hash, leaf.balance, root.hash, Fp::from(0)];
        let invalid_prover = MockProver::run(10, &circuit, vec![wrong_public_input]).unwrap();
        assert!(invalid_prover.verify().is_err());
    }
}

// #[cfg(feature = "dev-graph")]
// #[test]
// fn print_merkle_tree_3() {
//     use halo2_proofs::halo2curves::pasta::Fp;
//     use plotters::prelude::*;

//     let root =
//         BitMapBackend::new("prints/merkle-tree-3-layout.png", (1024, 3096)).into_drawing_area();
//     root.fill(&WHITE).unwrap();
//     let root = root
//         .titled("Merkle Tree 3 Layout", ("sans-serif", 60))
//         .unwrap();

//     let leaf = 99u64;
//     let elements = vec![1u64, 5u64, 6u64, 9u64, 9u64];
//     let indices = vec![0u64, 0u64, 0u64, 0u64, 0u64];
//     let digest: u64 = leaf + elements.iter().sum::<u64>();

//     let leaf_fp = Value::known(Fp::from(leaf));
//     let elements_fp: Vec<Value<Fp>> = elements
//         .iter()
//         .map(|x| Value::known(Fp::from(x.to_owned())))
//         .collect();
//     let indices_fp: Vec<Value<Fp>> = indices
//         .iter()
//         .map(|x| Value::known(Fp::from(x.to_owned())))
//         .collect();

//     let circuit = MerkleTreeV3Circuit {
//         leaf: leaf_fp,
//         path_elements: elements_fp,
//         path_indices: indices_fp,
//     };

//     halo2_proofs::dev::CircuitLayout::default()
//         .render(8, &circuit, &root)
//         .unwrap();
// }
