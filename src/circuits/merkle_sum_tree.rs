use super::super::chips::merkle_sum_tree::{MerkleSumTreeChip, MerkleSumTreeConfig};
use halo2_proofs::{circuit::*, plonk::*};
use std::marker::PhantomData;
use eth_types::Field;

#[derive(Default)]
struct MerkleSumTreeCircuit <F: Field> {
    pub leaf_hash: F,
    pub leaf_balance: F,
    pub path_element_hashes: Vec<F>,
    pub path_element_balances: Vec<F>,
    pub path_indices: Vec<F>,
    _marker: PhantomData<F>
}

impl <F:Field> Circuit<F> for MerkleSumTreeCircuit<F> {

    type Config = MerkleSumTreeConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {

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
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {

        let chip = MerkleSumTreeChip::construct(config);
        let (leaf_hash, leaf_balance) = chip.assing_leaf_hash_and_balance(layouter.namespace(|| "assign leaf"), F::from(self.leaf_hash), F::from(self.leaf_balance))?;

        chip.expose_public(layouter.namespace(|| "public leaf hash"), &leaf_hash, 0)?;
        chip.expose_public(layouter.namespace(|| "public leaf balance"), &leaf_balance, 1)?;

        // apply it for level 0 of the merkle tree
        // node cells passed as inputs are the leaf_hash cell and the leaf_balance cell
        let (mut next_hash, mut next_sum) = chip.merkle_prove_layer(
            layouter.namespace(|| format!("level {} merkle proof", 0)),
            &leaf_hash,
            &leaf_balance,
            self.path_element_hashes[0],
            self.path_element_balances[0],
            self.path_indices[0],
        )?;

        // apply it for the remaining levels of the merkle tree
        // node cells passed as inputs are the computed_hash_prev_level cell and the computed_balance_prev_level cell
        for i in 1..self.path_element_balances.len() {
            (next_hash, next_sum) = chip.merkle_prove_layer(
                layouter.namespace(|| format!("level {} merkle proof", i)),
                &next_hash,
                &next_sum,
                self.path_element_hashes[i],
                self.path_element_balances[i],
                self.path_indices[i],
            )?;
        }

        chip.expose_public(layouter.namespace(|| "public root"), &next_hash, 2)?;
        chip.expose_public(layouter.namespace(|| "public balance sum"), &next_sum, 3)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MerkleSumTreeCircuit;
    use super::super::super::chips::poseidon::spec::MySpec;
    use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength};
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr as Fp};
    use std::marker::PhantomData;

    const WIDTH: usize = 5;
    const RATE: usize = 4;
    const L: usize = 4;

    #[derive(Debug, Clone)]
    struct Node {
        pub hash: Fp,
        pub balance: Fp,
    }

    fn compute_merkle_sum_root(node: &Node,  elements: &Vec<Node>, indices: &Vec<Fp>) -> Node {
        let k = elements.len();
        let mut digest = node.clone();
        let mut message: [Fp; 4];
        for i in 0..k {
            if indices[i] == 0.into() {
                message = [Fp::from(digest.hash), Fp::from(digest.balance), Fp::from(elements[i].hash), Fp::from(elements[i].balance)];
            } else {
                message = [Fp::from(elements[i].hash), Fp::from(elements[i].balance), Fp::from(digest.hash), Fp::from(digest.balance)];
            }

            digest.hash = poseidon::Hash::<_, MySpec<Fp, WIDTH, RATE>, ConstantLength<L>, WIDTH, RATE>::init()
                .hash(message);

            digest.balance = digest.balance + elements[i].balance;
        }
        digest
    }

    fn instantiate_circuit(leaf: Node, elements: Vec<Node>, indices: Vec<Fp>) -> MerkleSumTreeCircuit<Fp>{

        let element_hashes: Vec<Fp> = elements.iter().map(|node| node.hash).collect();
        let element_balances: Vec<Fp> = elements.iter().map(|node| node.balance).collect();

        MerkleSumTreeCircuit {
            leaf_hash: leaf.hash,
            leaf_balance: leaf.balance,
            path_element_hashes: element_hashes,
            path_element_balances: element_balances,
            path_indices: indices,
            _marker: PhantomData,
        }

    }

    fn setup() -> (Node, Vec<Node>, Vec<Fp>, Node) {

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

        let indices = vec![Fp::from(0u64), Fp::from(0u64), Fp::from(0u64), Fp::from(0u64), Fp::from(0u64)];

        let root = compute_merkle_sum_root(&leaf, &elements, &indices);

        (leaf, elements, indices, root)
    }

    #[test]
    fn test_valid_merkle_sum_tree() {

        let (leaf, elements, indices, root) = setup();

        let public_input = vec![leaf.hash, leaf.balance, root.hash, root.balance];

        let circuit = instantiate_circuit(leaf, elements, indices);

        let valid_prover = MockProver::run(10, &circuit, vec![public_input]).unwrap();

        valid_prover.assert_satisfied();
    }

    #[test]
    fn test_invalid_root_balance() {

        let (leaf, elements, indices, root) = setup();

        let public_input = vec![leaf.hash, leaf.balance, root.hash, Fp::from(1000u64)];

        let circuit = instantiate_circuit(leaf, elements, indices);

        let invalid_prover = MockProver::run(10, &circuit, vec![public_input]).unwrap();

        // error => Err([Equality constraint not satisfied by cell (Column('Advice', 4 - ), in Region 22 ('merkle prove layer') at offset 1), Equality constraint not satisfied by cell (Column('Instance', 0 - ), outside any region, on row 3)])
        // computed_sum (advice column[4]) != root.sum (instance column row 3)
        assert!(invalid_prover.verify().is_err());
    }

    #[test]
    fn test_invalid_root_hash() {

        let (leaf, elements, indices, root) = setup();

        let public_input = vec![leaf.hash, leaf.balance, Fp::from(1000u64), root.balance];

        let circuit = instantiate_circuit(leaf, elements, indices);

        let invalid_prover = MockProver::run(10, &circuit, vec![public_input]).unwrap();

        // error => Err([Equality constraint not satisfied by cell (Column('Instance', 0 - ), outside any region, on row 2), Equality constraint not satisfied by cell (Column('Advice', 5 - ), in Region 26 ('permute state') at offset 36)])
        // computed_hash (advice column[5]) != root.hash (instance column row 2)
        assert!(invalid_prover.verify().is_err());
    }

    #[test]
    fn test_invalid_leaf_hash() {

        let (leaf, elements, indices, root) = setup();

        let public_input = vec![Fp::from(1000u64), leaf.balance, root.hash, root.balance];

        let circuit = instantiate_circuit(leaf, elements, indices);

        let invalid_prover = MockProver::run(10, &circuit, vec![public_input]).unwrap();

        // error => Equality constraint not satisfied by cell (Column('Advice', 0 - ), in Region 2 ('merkle prove layer') at offset 0). Equality constraint not satisfied by cell (Column('Instance', 0 - ), outside any region, on row 0)
        // leaf_hash (advice column[0]) != leaf.hash (instance column row 0)
        assert!(invalid_prover.verify().is_err());

    }

    #[test]
    fn test_invalid_leaf_balance() {

        let (leaf, elements, indices, root) = setup();

        let public_input = vec![leaf.hash, Fp::from(1000u64), root.hash, root.balance];

        let circuit = instantiate_circuit(leaf, elements, indices);

        let invalid_prover = MockProver::run(10, &circuit, vec![public_input]).unwrap();

        // error => Equality constraint not satisfied by cell (Column('Advice', 1 - ), in Region 2 ('merkle prove layer') at offset 0) Equality constraint not satisfied by cell (Column('Instance', 0 - ), outside any region, on row 1)
        // leaf_balance (advice column[1]) != leaf.balance (instance column row 1)
        assert!(invalid_prover.verify().is_err());
    }

    #[test]
    fn test_non_binary_index() {

        let (leaf, elements, mut indices, root) = setup();

        let public_input = vec![leaf.hash, leaf.balance, root.hash, root.balance];

        indices[0] = Fp::from(2);

        let circuit = instantiate_circuit(leaf, elements, indices);

        let invalid_prover = MockProver::run(10, &circuit, vec![public_input]).unwrap();

        // error: constraint not satisfied 'bool constraint'
        // error: constraint not satisfied 'swap constraint'
        assert!(invalid_prover.verify().is_err());
    }

    #[test]
    fn test_swapping_index() {

        let (leaf, elements, mut indices, root) = setup();

        let public_input = vec![leaf.hash, leaf.balance, root.hash, root.balance];

        indices[0] = Fp::from(1);

        let circuit = instantiate_circuit(leaf, elements, indices);

        let invalid_prover = MockProver::run(10, &circuit, vec![public_input]).unwrap();

        // error => Err([Equality constraint not satisfied by cell (Column('Instance', 0 - ), outside any region, on row 2), Equality constraint not satisfied by cell (Column('Advice', 5 - ), in Region 26 ('permute state') at offset 36)])
        // computed_hash (advice column[5]) != root.hash (instance column row 2)
        assert!(invalid_prover.verify().is_err());
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_merkle_sum_tree() {
        use plotters::prelude::*;

        let root =
            BitMapBackend::new("prints/merkle-sum-tree-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Merkle Sum Tree Layout", ("sans-serif", 60))
            .unwrap();

        let (leaf, elements, indices, _) = setup();

        let circuit = instantiate_circuit(leaf, elements, indices);

        halo2_proofs::dev::CircuitLayout::default()
            .render(8, &circuit, &root)
            .unwrap();
    }
}


