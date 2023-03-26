use super::super::chips::merkle_v1::{
    MerkleTreeV1Config, MerkleTreeV1Chip
};

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::*,
    plonk::*,
};

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

        MerkleTreeV1Chip::configure(meta, [col_a, col_b, col_c], bool_selector, swap_selector, hash_selector, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>
    ) -> Result<(), Error> {
        // We create a new instance of chip using the config passed as input
        let chip = MerkleTreeV1Chip::<F>::construct(config);

        let mut leaf_cell = chip.assing_leaf(layouter.namespace(|| "load leaf"), self.leaf)?;

        // Verify that the leaf matches the public input
        chip.expose_public(layouter.namespace(|| "leaf"), &leaf_cell, 0)?;

        // apply it for level 0 of the merkle tree
        let mut digest = chip.assign_hashing_region(
            layouter.namespace(|| "level 0"),
            &leaf_cell,
            self.path_elements[0],
            self.path_indices[0]
        )?;

        // apply it for the remaining levels of the merkle tree
        for i in 1..self.path_elements.len() {
            digest = chip.assign_hashing_region(
                layouter.namespace(|| "next level"),
                &digest,
                self.path_elements[i],
                self.path_indices[i]
            )?;
        }

        chip.expose_public(layouter.namespace(|| "root"), &digest, 1)?;

        Ok(())
    }

}


mod tests {
    use super::MerkleTreeV1Circuit;
    use halo2_proofs::{
        circuit::Value,
        dev::MockProver,
        halo2curves::pasta::Fp
};

    #[test]
    fn test_merkle_tree_1() {
        let leaf = Fp::from(99);
        let path_elements = vec![Value::known(Fp::from(1)), Value::known(Fp::from(1))];
        let path_indices = vec![Value::known(Fp::from(0)), Value::known(Fp::from(0))];
        let digest = Fp::from(101);

        let circuit = MerkleTreeV1Circuit {
            leaf: Value::known(leaf),
            path_elements: path_elements,
            path_indices: path_indices,
        };

        // succesful case
        let public_input = vec![leaf, digest];
        let prover = MockProver::run(4, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();

        // not successful case
        let public_input = vec![leaf, Fp::from(102)];
        let prover = MockProver::run(4, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();

        // not successful case
        let public_input = vec![Fp::from(100), digest];
        let prover = MockProver::run(4, &circuit, vec![public_input.clone()]).unwrap();
        assert!(prover.verify().is_err());
    }
}