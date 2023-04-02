# halo2-experiments

For practice to using halo2

This library makes use of the [PSE Fork of Halo2](https://github.com/privacy-scaling-explorations/halo2).

List of available experiments: 

- [Experiment 1 - Inclusion Check](#experiment-1---inclusion-check)
- [Experiment 2 - Inclusion Check V2](#experiment-2---inclusion-check-v2)
- [Experiment 3 - Dummy Hash V1](#experiment-3---dummy-hash-v1)
- [Experiment 4 - Dummy Hash V2](#experiment-4---dummy-hash-v2)
- [Experiment 5 - Merkle Tree V1](#experiment-5---merkle-tree-v1)
- [Experiment 6 - Merkle Tree V2](#experiment-6---merkle-tree-v2)
- [Experiment 7 - Poseidon Hash](#experiment-7---poseidon-hash)
- [Experiment 8 - Merkle Tree v3](#experiment-8---merkle-tree-v3)

# Experiment 1 - Inclusion Check

The inclusion check Chip is a Chip built using 2 advice columns, 1 selector column and 1 instance column. The advice columns contain the list of usernames and balances. The instance column contains the username and balance of the user that I am generating the proof for. Let's call it `pubUsername` and `pubBalance` This should be public and the snark should verify that there's a row in the advise column where `pubUsername` and `pubBalance` entries match. At that row the selector should be turned on.

| username  | balance  |instance  |
| ----      | ---      |        --- |
| 12332 | 200 | 56677
| 56677 | 100 | 100
| 45563 | 700 | 

The constraint is enforced as a permutation check between the cell of the advice column and the cell of the instance column.

In this example, we don't really need a selector as we are not enforcing any custom gate.

`cargo test -- --nocapture test_inclusion_check_1`
`cargo test --all-features -- --nocapture print_inclusion_check`

### Configuration

The 2 advice columns and the 1 instance column are instantiated inside the `configure` function of the circuit and passed to the `configure` function of the chip. That's because in this way these columns can be shared across different chips inside the same circuit (although this is not the case). 

Q: What is PhantomData?

A: In Rust, std::{marker::PhantomData} is a struct that has no fields and is used to indicate to the compiler that a type parameter or a generic type argument is being used in the code, even though it doesn't appear directly in any of the struct's fields or methods. An example of that can be found => https://github.com/enricobottazzi/halo2-fibonacci-ex/blob/master/src/bin/example3.rs#L137 or inside the `InclusionCheckChip` struct in the inclusion_check example

Q: How do you define the InclusionCheckChip struct?

A: In Rust, when you define a struct with a type parameter, such as `InclusionCheckChip<F>`, you are creating a generic struct that can work with any type that satisfies certain constraints. In this case, the type parameter F has a constraint : Field, which means that F must implement the Field trait.

# Experiment 2 - Inclusion Check V2

| username  | balance  | usernameAcc | balanceAcc| selector  | instance  |
| ----      | ---      |   ---     |       --- | -- | --| 
| - | - |  0 | 0 | -  | 56677
| 12332 | 200 |  0 | 0 |  0  | 100
| 56677 | 100 |  56677| 100 | 1  | -
| 45563 | 700 |  56677| 100| 0  | -

The constraint is enforced as a permutation check between the cell of the advise column and the cell of the instance column. In this example:

- We need to use the selector to be turned on on the required line to enforce the custom gate
- The permutation check is enforced between the last row of the `usernameAcc` and `balanceAcc` columns and the instance column values

### Configuration

The 4 advice columns and the 1 instance column are instantiated inside the `configure` function of the circuit and passed to the `configure` function of the chip. That's because in this way these columns can be shared across different chips inside the same circuit (although this is not the case). The selector is instantiated inside the `configure` function of the chip. That's because this selector is specific for the InclusionCheck chip and doesn't need to be shared across other chips.

`cargo test -- --nocapture test_inclusion_check_2`

# Experiment 3 - Dummy Hash V1

Experiment of a dummy hash from [`halo2-merkle-tree`](https://github.com/jtguibas/halo2-merkle-tree/blob/main/src/chips/hash_1.rs).

The dummy hash function is `2 * a = b`. 

`a` can be viewed as the input of the hash function. `b` is the output of the hash function. 
The zk snark verifies that the prover knows `a` such that the output of the hash function is equal to `b`.

| a  | b  |hash selector | instance
| -- | -  |  ---         | ---
| 2  | 4  | 1            | 4

`a` and `b` here are the advice column, namely the private inputs of circuit.

The instance column contains the public input of the circuit namely the result of the hash function that the zk snark should verify.

`cargo test -- --nocapture test_hash_1`

### Configuration

The 2 advice columns and the 1 instance column are instantiated inside the `configure` function of the circuit and passed to the `configure` function of the chip. That's because in this way these columns can be shared across different chips inside the same circuit (although this is not the case). The hash selector is instantiated inside the `configure` function of the chip. That's because this selector is specific for the InclusionCheck chip and doesn't need to be shared across other chips.

# Experiment 4 - Dummy Hash V2

Experiment of a dummy hash from [`halo2-merkle-tree`](https://github.com/jtguibas/halo2-merkle-tree/blob/main/src/chips/hash_2.rs).

The dummy hash function is `a + b = c`. 

`a` and `b` can be viewed as the input of the hash function. `c` is the output of the hash function. 
The zk snark verifies that the prover knows `a` and `b` such that the output of the hash function is equal to `c`.

| a  | b  | c  |hash selector | instance
| -- | -  |--- | ---          | ---
| 2  | 7  | 9  | 1            | 9

`a` and `b` and `c` here are the advice column, namely the private inputs of circuit.

The instance column contains the public input of the circuit namely the result of the hash function that the zk snark should verify.

### Configuration

Same as dummy hash V2.

`cargo test -- --nocapture test_hash_2`

# Experiment 5 - Merkle Tree V1

Experiment of a merkle tree from [`halo2-merkle-tree`](https://github.com/jtguibas/halo2-merkle-tree/blob/main/src/chips/hash_2.rs).

The dummy hash function for the merkle tree is `a + b = c`. 

The chip is made of 3 advice columns `a`, `b` and `c`, 3 selector columns `bool_selector`, `swap_selector` and `hash_selector` and 1 instance column `instance`.

The input passed to instantiate a circuit are the `leaf` the we are trying to prove the inclusion of in the tree, `path_elements` which is an array of the siblings of the leaf and `path_indices` which is an array of bits indicating the relative position of the node that we are performing the hashing on to its sibilings (`path_elements`). For example a path index of `1` means that the sibling is on the left of its node, while a path index of `0` means that the sibling is on the right of its node. Therefore the hashing needs to be performed in a specific order. Note that considering our dummy hash, the order of the hashing is not important as the result is the same. But this will be important when implementing a real hash function.

The assignment of the values to the columns is performed using a region that covers 2 rows:

| a           | b                | c       | bool_selector | swap_selector | hash_selector
| --          | -                | --      |    --         | ---           | ---
| leaf        | path_element     | index   |     1         | 1             | 0
| input left  | input right      | digest  |     0         | 0             | 1

At row 0, we assign the leaf, the element (from `path_element`) and the bit (from `path_indices`). At this row we turn on `bool_selector` and `swap_selector`. 

At row 1, we assign the input left, the input right and the digest. At this row we turn on `hash_selector`.

The chip contains 3 custom gates: 

- If the `bool_selector` is on, checks that the value inside the c column is either 0 or 1
- If the `swap_selector` is on, checks that the swap on the next row is performed correctly according to the `bit`
- If the `hash_selector` is on, checks that the digest is equal to the (dummy) hash between input left and input right

Furthermore, the chip contains 2 permutation check:

- Verifies that the last `digest` is equal to the `root` of the tree which is passed as (public) value to the instance column

### Configuration

The MerkleTreeV1Config contains 3 advice column, 1 bool_selector, 1 swap_selector, 1 hash_selector, and 1 instance column. The advice columns and the instance column are instantiated inside the `configure` function of the circuit and passed to the `configure` function of the chip. That's because in this way these columns can be shared across different chips inside the same circuit (although this is not the case). The selectors are instantiated inside the `configure` function of the chip. That's because these selectors are specific for the MerkleTreeV1 chip and don't need to be shared across other chips.

`cargo test -- --nocapture test_merkle_tree_1`

# Experiment 6 - Merkle Tree V2

This Merkle Tree specification works exactly the same as the previous one. The only difference is that it makes use of the `Hash2Chip` and `Hash2Config` created in experiment 4 rather than rewriting the logic of the hash inside the MerkleTree Chip, as it was done in experiment 5. 

### Configuration

It's worth nothing how the `Hash2Chip` and `Hash2Config` are used in this circuit. As mentioned in the [Halo2 book - Composing Chips](https://zcash.github.io/halo2/concepts/chips.html#composing-chips) these should be composed as in a tree. 

- MerkleTreeV2Chip
    - Hash2Chip

The MerkleTreeV2Config contains 3 advice column, 1 bool_selector, 1 swap_selector, 1 instance column and the Hash2Config.

The advice columns and the instance column are instantiated inside the `configure` function of the circuit and passed to the `configure` function of the MerkleTreeV2Chip. That's because in this way these columns can be shared across different chips inside the same circuit (although this is not the case). The bool_selector and swap_seletor are instantiated inside the `configure` function of the MerkleTreeV2Chip. That's because these selectors are specific for the MerkleTreeV2Chip and don't need to be shared across other chips. The child chip Hash2Chip is instantiated inside the `configure` function of the MerkleTreeV2Chip. That's because the Hash2Chip is specific for the MerkleTreeV2Chip by passing in the advice columns and the instance column that are shared between the two chips. In this way we can leverage `Hash2Chip` with its gates and its assignment function inside our MerkleTreeV2Chip. 

`cargo test -- --nocapture test_merkle_tree_1`


# Experiment 7 - Poseidon Hash

Create a chip that performs a Poseidon hash leveraging the gadget provided by the Halo2 Library.
Based on this implementation => https://github.com/jtguibas/halo2-merkle-tree/blob/main/src/circuits/poseidon.rs

The PoseidonChip, compared to the Pow5Chip gadget provided by the Halo2Library, adds one advice column that takes the input of the hash function and one instance column that takes the expected output of the hash function.

### Configuration

The configuration tree looks like this:

- PoseidonChip
    - Pow5Chip

The PoseidonConfig contains a vector of advice columns, 1 instance column and the Pow5Config.

The vector of advice columns and the instance column are instantiated inside the `configure` function of the circuit and passed to the `configure` function of the PoseidonChip. That's because in this way these columns can be shared across different chips inside the same circuit (although this is not the case). Further columns part of the configuration of the `Pow5Chip` are created inside the `configure` function of the PoseidonChip and passed to the configure function of the `Pow5Chip`

The bool_selector and swap_seletor are instantiated inside the `configure` function of the MerkleTreeV2Chip. That's because these selectors are specific for the MerkleTreeV2Chip and don't need to be shared across other chips. The child chip Hash2Chip is instantiated inside the `configure` function of the MerkleTreeV2Chip. That's because the Hash2Chip is specific for the MerkleTreeV2Chip by passing in the advice columns and the instance column that are shared between the two chips. In this way we can leverage `Hash2Chip` with its gates and its assignment function inside our MerkleTreeV2Chip. 

At proving time:

- We instatiate the PoseidonCircuit with the input of the hash function and the expected output of the hash function

```rust
        let input = 99u64;
        let hash_input = [Fp::from(input), Fp::from(input), Fp::from(input)];

        // compute the hash outside of the circuit
        let digest =
            poseidon::Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash(hash_input);
        
        let circuit = PoseidonCircuit::<Fp, P128Pow5T3, 3, 2, 3> {
            hash_input: hash_input.map(|x| Value::known(x)),
            digest: Value::known(digest),
            _spec: PhantomData,
        };
```

In particular we can see that the poseidon hash is instantiated using different parameters such as P128Pow5T3, ConstantLength<3>, 3, 2 (when performing the hash), and P128Pow5T3, 3, 2, 3 when instantiating the circuit. These values represent poseidon specific parameters such as the number of rounds to be performed.  The only thing that we should care about in our APIs is `ConstantLength<n>` and the [parameter L in the PoseidonCircuit struct](https://github.com/summa-dev/halo2-experiments/blob/poseidon-hash/src/circuits/poseidon.rs#L16). This represent the number of inputs of the hash function and can be modified by the developer.

- The columns (`hash_inputs`, `instance`) are created in the [`configure` function of the PoseidonCircuit](https://github.com/summa-dev/halo2-experiments/blob/poseidon-hash/src/circuits/poseidon.rs#L41). All the other columns (the columns to be passed to the `pow5_config`) are created in the `configure` function of the Poseidon Chip. This function returns the PoseidonConfig instantiation. 

- The instantiation of the PoseidonConfig is passed to the `syntesize` function of the PoseidonCircuit. This function will pass the input values for the witness generation to the chip that will take care of assigning the values to the columns and verifying the constraints.

Test:

`cargo test -- --nocapture test_poseidon`
`cargo test --all-features -- --nocapture print_poseidon`

# Experiment 8 - Merkle Tree V3

This experiment re-implements the Merkle Tree circuit of experiment 6 using the PoseidonChip created in experiment 7. 

### Configuration

The Configuration tree looks like this:

- MerkleTreeV3Chip
    - PoseidonChip
        - Pow5Chip

The MerkleTreeV3 Config contains 3 advice columns, 1 instance column, a boolean selector, a swap selector and the PoseidonConfig.

The 3 advice columns and the instance column are instantiated inside the `configure` function of the circuit and passed to the `configure` function of the MerkleTreeV3Chip. That's because in this way these columns can be shared across different chips inside the same circuit (although this is not the case). The bool_selector and swap_seletor are instantiated inside the `configure` function of the MerkleTreeV3Chip. That's because these selectors are specific for the MerkleTreeV3Chip and don't need to be shared across other chips. 

The child chip PoseidonChip is instantiated inside the `configure` function of the MerkleTreeV2Chip. In this way we can leverage `PoseidonChip` with its gates and its assignment function inside our MerkleTreeV2Chip.

`cargo test -- --nocapture test_merkle_tree_3`
`cargo test --all-features -- --nocapture print_merkle_tree_3`

TO DO: 
- [x] Replace usage of constants in Inclusion Check.
- [x] Verifies that the leaf used inside the circuit is equal to the `leaf` passed as (public) value to the instance column
- [x] Add 2 public inputs to merkle_v1

# Experiment 9 - LessThan Chip with Dynamic Lookup Table V1

This Chip takes an input inside the input column advice. Say that we want to check if the input is less than 5. The instance column will be loaded with the values 0, 1, 2, 3, 4. The chip will then copy each value contained in the instance column to an `advice_table` advice column. The chip set a constraint on input to be less than 5 by creating a dynamic lookup check between the input and the `advice_table` column. If the input is less than 5, then the lookup will be successful and the constraint will be satisfied.

The dynamic constraint is set using the `lookup_any` API. The dynamic caracteristic is needed to let the prover add the value to compare `input` with at witness generation time.

TO DO:
- [x] Make it generic for Field F
- [x] Describe it

# Experiment 10 - LessThan Chip V2

This LessThan Chip works similarly to the one defined inside the [ZK-evm circuits gadgets](https://github.com/privacy-scaling-explorations/zkevm-circuits/blob/main/gadgets/src/less_than.rs). The LessThan Chip takes two values that are part of the witness (`lhs` and `rhs`) and returns 1 if `lhs < rhs` and 0 otherwise.

### Configuration

The LessThan Chip Configuration contains: 

- 1 advice column `lt` that denotes the result of the comparison: 1 if `lhs < rhs` and 0 otherwise
- An array of `diff` advice columns of length N_BYTES. It is basically the difference between `lhs` and `rhs` expressed in 8-bit chunks.
- An field element `range` that denotes the range in which both `lhs` and `rhs` are expected to be. This is calculated as `2^N_BYTES * 8` where `N_BYTES` is the number of bytes that we want to use to represent the values `lhs` and `rhs`.

The configure function takes as input the lhs and rhs virtual cells from a higher level chip and enforces the following gate:

`lhs - rhs - diff + (lt * range) = 0`

The assignment function takes as input the lhs and rhs values and assigns the values to the columns such that:

- `lhs < rhs` bool is assigned to the `lt` advice column
- if `lhs < rhs`, `lhs - rhs + range` is assigned to the `diff` advice columns
- else `lhs - rhs` is assigned to the `diff` advice columns

Now the custom gate should make more sense. Considering an example where `lhs = 5` and `rhs = 10` and N_BYTES is 1. Range would be 256 and diff would be a single advice column containing the value 251. The gate would be:

    `5 - 10 - 251 + (1 * 256) = 0`

Considering an example where `lhs = 10` and `rhs = 5` and N_BYTES is 1. Range would be 256 and diff would be a single advice column containing the value 5. The gate would be:

    `10 - 5 - 5 + (0 * 256) = 0`

The [`less_than_v2` circuit](./src/circuits/less_than_v2.rs) contains the instruction on how to use the LessThan Chip in a higher level circuit. The only added gate is that the `check` value in the advice column of the higher level circuit (which is the expected result of the comparison) should be equal to the `lt` value in the advice column of the LessThan Chip.

TO DO: 
- [ ] Add utils - create bool_check component for that
- [ ] Check whether it is possible to import it from the zkevm circuits lib.
- [ ] What are expressions?
- [ ] Implement range check for diff chunks












