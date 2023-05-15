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
- [Experiment 9 - LessThan Chip with Dynamic Lookup Table V1](#experiment-9---lessthan-chip-with-dynamic-lookup-table-v1)
- [Experiment 10 - LessThan Chip V2](#experiment-10---lessthan-chip-v2)
- [Experiment 11 - LessThan Chip V3](#experiment-11---lessthan-chip-v3)
- [Experiment 12 - Merkle Sum Tree](#experiment-12---merkle-sum-tree)
- [Experiment 13 - Add Carry v1](#experiment-13---add-carry-v1)
- [Experiment 14 - Add Carry v2](#experiment-14---add-carry-v2)
- [Experiment 15 - Overflow Check](#experiment-15---overflow-check)
- [Experiment 16 - Overflow Check v2](#experiment-16---overflow-check-v2)
- [Experiment 17 - Safe Accumulator](#experiment-17---safe-accumulator)

# Run

`cargo test --all-features -- --nocapture`

This command will test all the circuits and print the representation of the circuits inside the `prints` folder.

# Experiment 1 - Inclusion Check

The inclusion check Chip is a Chip built using 2 advice columns, 1 selector column and 1 instance column. The advice columns contain the list of usernames and balances. The instance column contains the username and balance of the user that I am generating the proof for. Let's call it `pubUsername` and `pubBalance` This should be public and the snark should verify that there's a row in the advise column where `pubUsername` and `pubBalance` entries match. At that row the selector should be turned on.

| username  | balance  |instance  |
| ----      | ---      |        --- |
| 12332 | 200 | 56677
| 56677 | 100 | 100
| 45563 | 700 | 

The constraint is enforced as a permutation check between the cell of the advice column and the cell of the instance column.

In this example, we don't really need a selector as we are not enforcing any custom gate.

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

Furthermore, the chip contains a permutation check:

- Verfies that the `leaf` is equal to the `leaf` passed as (public) value to the instance column
- Verifies that the last `digest` is equal to the `root` of the tree which is passed as (public) value to the instance column

### Configuration

The MerkleTreeV1Config contains 3 advice column, 1 bool_selector, 1 swap_selector, 1 hash_selector, and 1 instance column. The advice columns and the instance column are instantiated inside the `configure` function of the circuit and passed to the `configure` function of the chip. That's because in this way these columns can be shared across different chips inside the same circuit (although this is not the case). The selectors are instantiated inside the `configure` function of the chip. That's because these selectors are specific for the MerkleTreeV1 chip and don't need to be shared across other chips.

# Experiment 6 - Merkle Tree V2

This Merkle Tree specification works exactly the same as the previous one. The only difference is that it makes use of the `Hash2Chip` and `Hash2Config` created in experiment 4 rather than rewriting the logic of the hash inside the MerkleTree Chip, as it was done in experiment 5. 

### Configuration

It's worth nothing how the `Hash2Chip` and `Hash2Config` are used in this circuit. As mentioned in the [Halo2 book - Composing Chips](https://zcash.github.io/halo2/concepts/chips.html#composing-chips) these should be composed as in a tree. 

- MerkleTreeV2Chip
    - Hash2Chip

The MerkleTreeV2Config contains 3 advice column, 1 bool_selector, 1 swap_selector, 1 instance column and the Hash2Config.

The advice columns and the instance column are instantiated inside the `configure` function of the circuit and passed to the `configure` function of the MerkleTreeV2Chip. That's because in this way these columns can be shared across different chips inside the same circuit (although this is not the case). The bool_selector and swap_seletor are instantiated inside the `configure` function of the MerkleTreeV2Chip. That's because these selectors are specific for the MerkleTreeV2Chip and don't need to be shared across other chips. The child chip Hash2Chip is instantiated inside the `configure` function of the MerkleTreeV2Chip. That's because the Hash2Chip is specific for the MerkleTreeV2Chip by passing in the advice columns and the instance column that are shared between the two chips. In this way we can leverage `Hash2Chip` with its gates and its assignment function inside our MerkleTreeV2Chip. 

# Experiment 7 - Poseidon Hash

Create a chip that performs a Poseidon hash leveraging the gadget provided by the Halo2 Library.
Based on this implementation => https://github.com/jtguibas/halo2-merkle-tree/blob/main/src/circuits/poseidon.rs

The PoseidonChip, compared to the Pow5Chip gadget provided by the Halo2Library, adds a vector of advice columns that takes the input of the hash function and one instance column that takes the expected output of the hash function.

Similarly to the previous experiment, the PoseidonChip is a the top-level chip of the circuit while the Pow5Chip can be seen as a child chip as you can see from the configuration of the PoseidonChip

The configuration tree looks like this:

- PoseidonChip
    - Pow5Chip

The PoseidonConfig contains a vector of advice columns, 1 instance column and the Pow5Config.

The vector of advice columns and the instance column are instantiated inside the `configure` function of the circuit and passed to the `configure` function of the PoseidonChip. In particular the vector of advice columns contains as many columns as the WIDTH of the Poseidon hash function (more details later).

That's because in this way these columns can be shared across different chips inside the same circuit (although this is not the case). Further columns part of the configuration of the `Pow5Chip` are created inside the `configure` function of the PoseidonChip and passed to the configure function of the `Pow5Chip`.

## Functioning Logic

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

- The instantiation of the PoseidonConfig is passed to the `syntesize` function of the PoseidonCircuit. This function will pass the input values for the witness generation to the chip that will take care of assigning the values to the columns and verifying the constraints. In particular, it will:

    - call `load_private_inputs` on the poseidon chip to assign the hash input values to the advice columns `hash_inputs`. This function will return the assigned cells inside the advice columns `hash_inputs`
    - call `hash` on the poseidon chip passing the hash input values to the advice columns `hash_inputs`. This function will return the assigned cells inside the advice columns `hash_inputs`. Later it will initialize the `pow5_chip` and call the `hash` function on the `pow5_chip` passing the `hash_input` column. This function will return an assigned cell that represents the constrained output of the hash function.
    - call the `expose_public` function on the poseidon chip by passing in the assigned cell output of the `hash` function. This function will constrain it to be equal to the expected hash output passed into the public instance column.

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

## Functioning Logic

At proving time:

- We instatiate the MerkleTreeV3 Circuit with the leaf, the path_elements and the path_indices

- The 3 advice columns and the instance column are created in the `configure` function of the MerkleTreeV3 Circuit. All the other columns (`hash_inputs`, namely the columns to be passed to the `poseidon config`) are created in the `configure` function of the MerkleTreeV3 Chip. This function returns a MerkleTreeV3Config instance. 

- The instantiation of the PoseidonConfig is passed to the `syntesize` function of the PoseidonCircuit. This function will pass the input values for the witness generation to the chip that will take care of assigning the values to the columns and verifying the constraints. In particular, it will:

    - call `assign leaf` on the merkle tree chip to leaf value inside a cell in the advice column `a`. This function will return the assigned cells.
    - call the `expose_public` function on the merkle tree chip by passing in the assigned cell output of the `assign leaf` function. This function will constrain it to be equal to the expected leaf hash passed into the public instance column.
    - call the `merkle_prover_layer` function on the chip for each level of the merkle tree. 
    - call the `expose_public` function by passing in the last output of the `merkle_prove_layer` function. This function will constrain it to be equal to the expected root passed into the public instance column.

# Experiment 9 - LessThan Chip with Dynamic Lookup Table V1

This Chip takes an input inside the input column advice. Say that we want to check if the input is less than 5. The instance column will be loaded with the values 0, 1, 2, 3, 4. The chip will then copy each value contained in the instance column to an `advice_table` advice column. The chip set a constraint on input to be less than 5 by creating a dynamic lookup check between the input and the `advice_table` column. If the input is less than 5, then the lookup will be successful and the constraint will be satisfied.

The dynamic constraint is set using the `lookup_any` API. The dynamic caracteristic is needed to let the prover add the value to compare `input` with at witness generation time.

TO DO:
- [x] Make it generic for Field F
- [x] Describe it

# Experiment 10 - LessThan Chip V2

This LessThan Chip is imported from the [ZK-evm circuits gadgets](https://github.com/privacy-scaling-explorations/zkevm-circuits/blob/main/gadgets/src/less_than.rs). The LessThan Chip takes two values that are part of the witness (`lhs` and `rhs`) and returns 1 if `lhs < rhs` and 0 otherwise.

### Configuration

The LessThan Chip Configuration contains: 

- 1 advice column `lt` that denotes the result of the comparison: 1 if `lhs < rhs` and 0 otherwise
- An array of `diff` advice columns of length N_BYTES. It is basically the difference between `lhs` and `rhs` expressed in 8-bit chunks.
- An field element `range` that denotes the range in which both `lhs` and `rhs` are expected to be. This is calculated as `2^N_BYTES * 8` where `N_BYTES` is the number of bytes that we want to use to represent the values `lhs` and `rhs`.

The configure function takes as input the lhs and rhs virtual cells from a higher level chip and enforces the following gate:

`lhs - rhs - diff + (lt * range) = 0`

Note that the gate enforces inside this child chip, the constraint is dependent on the value of some cells passed from an higher level chip. The parent chip and the child chip are sharing a region. That's why the `assign` function inside the `LTChip` takes as input the `region` rather than the `layouter` as usual.

The assignment function takes as input the lhs and rhs values and assigns the values to the columns such that:

- `lhs < rhs` bool is assigned to the `lt` advice column
- if `lhs < rhs`, `lhs - rhs + range` is assigned to the `diff` advice columns
- else `lhs - rhs` is assigned to the `diff` advice columns

Again, note that the assignment function doesn't take assigned value of type `Value<F>` but simple values of type `F` where F is a generic Field Element. This example makes clear the difference between `assignment` and `setting constraints`. The assignment function is responsible for assigning values to the columns. You can perform the assignemnt starting from values that are not necessarily computed from the circuit itself. The constraint function is responsible for setting the constraints between the columns, this process is prior and independent to the assignment/witness generation.

Now the custom gate should make more sense. Considering an example where `lhs = 5` and `rhs = 10` and N_BYTES is 1. Range would be 256 and diff would be a single advice column containing the value 251. The gate would be:

    `5 - 10 - 251 + (1 * 256) = 0`

Considering an example where `lhs = 10` and `rhs = 5` and N_BYTES is 1. Range would be 256 and diff would be a single advice column containing the value 5. The gate would be:

    `10 - 5 - 5 + (0 * 256) = 0`

The [`less_than_v2` circuit](./src/circuits/less_than_v2.rs) contains the instruction on how to use the LessThan Chip in a higher level circuit. The only added gate is that the `check` value in the advice column of the higher level circuit (which is the expected result of the comparison) should be equal to the `lt` value in the advice column of the LessThan Chip.

Lastly, let's consider a case where lhs lies outside the range. For example `lhs = 1` and `rhs = 257` and N_BYTES is 1. Diff is a single advice column but it can't represent the value 256 in 8 bits!

TO DO: 
- [x] Understand the whole functioning 
- [x] Check whether it is possible to import it from the zkevm circuits lib.
- [x] Need to enforce the LT expression to be equal to 1 on a higher-level circuit!

# Experiment 11 - LessThan Chip V3

This experiment makes use of the same chip as in V2. The only difference here is that on the higher level circuit level we impose the LessThan value to be constrained to 1.

~~The only difference here is the additional constraint added at line 61~~

~~`vec![..., q_enable * (Expression::Constant(F::from(1)) - check)]`~~

This property is constrained by assigning 1 to the check in the synthesize function. The constraint set inside the top level circuit checks that check is equal to lt in the child chip. 

The Circuit built on top of that chip (`circuits/less_than_v3.rs`) also makes use of the `hash_v1` chip. This is just an experiment to remark that you can reuse the generic Field trait from `eth_types::{Field}` to instantiate a chip that is generic on a Field of trait F from halo2_proofs::arithmetic::FieldExt. That's because the Field trait is a wrapper around the FieldExt type (and other 2 types) => https://github.com/privacy-scaling-explorations/zkevm-circuits/blob/4cfccfa6c3b251284ff61eeb907d548d59206753/eth-types/src/lib.rs#LL51C72-L51C72. 

It means that you can use the eth_field::Field type to instantiate a chip that is generic on a F that implements the FieldExt trait.

# Experiment 12 - Merkle Sum Tree

This chip implements the logic of a [Merkle Sum Tree](https://github.com/summa-dev/pyt-merkle-sum-tree). The peculiarity of a Merkle Sum Tree are that:

- Each node inside the tree (both Leaf Nodes and Middle Nodes) contains an hash and a value.
- Each Leaf Node contains a hash and a value.
- Each Middle Node contains a hash and a value where hash is equal to `Hash(left_child_hash, left_child_sum, right_child_hash, right_child_sum)` and value is equal to `left_child_sum + right_child_sum`.

A level inside the tree consists of the following region inside the chip:

For the level 0 of the tree:

| a                | b                     | c               |    d              |   e        |  bool_selector | swap_selector |  sum_selector
| --               | -                     | --              |   ---             |  ---       |    --          | ---           |  ---
| leaf_hash        | leaf_balance          | element_hash    |element_balance    | index      |        1       | 1             |  0
| input_left_hash  | input_left_balance    | input_right_hash|input_right_balance|computed_sum|     0          | 0             |  1

At row 0, we assign the leaf_hash, the leaf_balance, the element_hash (from `path_element_hashes`), the element_balance (from `path_element_balances`) and the bit (from `path_indices`). At this row we turn on `bool_selector` and `swap_selector`.

At row 1, we assign the input_left_hash, the input_right_balance, the input_right_hash, the input_right_balance and the digest. 
At this row we activate the `poseidon_chip` and call the `hash` function on that by passing as input cells `[input_left_hash, input_left_balance, input_right_hash, input_right_balance]`. This function will return the assigned cell containing the `computed_hash`.

The chip contains 4 custom gates: 

- If the `bool_selector` is on, checks that the value inside the c column is either 0 or 1
- If the `swap_selector` is on, checks that the swap on the next row is performed correctly according to the `bit`
- If the `sum_selector` is on, checks that the sum between the `input_left_balance` and the `input_right_balance` is equal to the `computed_sum`
- checks that the `computed_hash` is equal to the hash of the `input_left_hash`, the `input_left_balance`, the `input_right_hash` and the `input_right_balance`. This hashing is enabled by the `poseidon_chip`.

For the other levels of the tree:

| a                         | b                       | c              |    d              |   e         | bool_selector | swap_selector | sum_selector  
| --                        | -                       | --             |   ---             |  ---        |  --           | ---           |  ---
| computed_hash_prev_level  | computed_sum_prev_level | element_hash   |element_balance    | index       |      1        | 1             |  0
| input_left_hash           | input_left_balance      |input_right_hash|input_right_balance|computed_sum |     0         | 0             |  1

When moving to the next level of the tree, the `computed_hash_prev_level` is copied from the `computed_hash` of the previous level. While the `computed_sum_prev_level` is copied from the `computed_sum` at the previous level.

Furthermore, the chip contains four permutation check:

- Verfies that the `leaf_hash` is equal to the `leaf_hash` passed as (public) value to the instance column
- Verfies that the `leaf_balance` is equal to the `leaf_balance` passed as (public) value to the instance column
- Verifies that the last `computed_hash` is equal to the (expected) `root` of the tree which is passed as (public) value to the instance column
- Verifies that the last `computed_sum` is equal to the (expected) `balance_sum` of the tree which is passed as (public) value to the instance column

TO DO: 
- [x] Replace usage of constants in Inclusion Check.
- [ ] Fix printing functions
- [ ] Check the security of the Poseidon Hash



# Experiment 13 - Add carry v1

Allowing the addition of new values to previously accumulated amounts into two columns, acc_hi and acc_lo.

Circuit looks like this,

| - | value  | acc_hi(x * 2^16)  | acc_lo(x * 2^0) | instance  |
| - | ----      | ---      |   ---      | --|
| 0 | - | 0 |  0 | 0x1 |
| 1 | 0xffff | 0 |  0xffff | 0 |
| 2 | 0x1 | 0x1 | 0 | - |
| 3 | - | - | - | - |

### Configuration 

the first rows's values assigned with zero. And `assign_advice_row` function needs values for addition, these will be copied cell from the region. and then permutation check like below. 

```Rust
// following above table
0 == (value + (acc_hi[1] * (1 << 16)) + acc_lo[1]) 
    - ((acc_hi[2] * (1 << 16)) + acc_lo[2] )

```

`cargo test --package halo2-experiments --lib -- circuits::add_carry_v1`

TO DO: -> moved to next version.

~~- [ ] Range check for left most column of multi-columns for accumulation~~<br>
~~- [ ] Support 2^256 in Accumulated value with multi-columns~~

# Experiment 14 - Add carry v2

Allowing the addition of new values to previously accumulated amounts into two columns, acc_hi and acc_lo.

Circuit looks like this

| - | value | acc_hi_inv | acc_hi(x * 2^16)  | acc_lo(x * 2^0) | instance  |
| - | ----  | ---   | ---      |   ---      | --|
| 0 | - | - |  0 |  0xfffe | 0x1 |
| 1 | 0x1 | * |  0 | 0xffff | 0xfffe |
| 2 | - | - | - | - | 0x0 |
| 3 | - | - | - | - | 0x1 |

### Configuration 

As similar like v1, used simple configuration. but added one more constraint with one more advice column for inverted number. this constraint polynomial followed `is_zero` gadget from `zkevm-circuit`.
the addition constraint like below.

```Rust
// following above table
0 == acc_hi[1] * (1 - acc_hi[1] * acc_hi_inv[1]) 

```

# Experiment 15 - Overflow Check

This chip implemented an overflow checking for columns of the accumulation amount of assets.
There is an extra column for accumulating value. the column be used for inverting a number in the overflow column.

There are two selectors in this chip.
- 'add_carry_selector': toggle sum of new value in 'a' column and accumulated value.
- 'overflow_check_selector': toggle check to see if the sum in the 'sum_overflow' column equals zero.

for checking if a number is zero in the 'sum_overflow' column, activate 'is_zero' chip.<br>
The code for the 'is_zero' chip was taken from the "halo2-example" repository.

There are two tests for 'overflow circuit'.

- None overflow case
    | - | value | sum_overflow_inv | sum_overflow | sum_hi(x * 2^16)  | sum_lo(x * 2^0) | instance  |
    | - | - | - | - | - | - | - |
    | 0 | - | - | - |  0 |  0xfffe | 0 |
    | 1 | 0x1_0003 | * | * |  0x2 | 0x1 | 0xfffe |
    | 2 | - | - | - | - | - | 0x2 |
    | 3 | - | - | - | - | - | 0x1 |

At row 1, We can calculated 'acc_hi' has 0x20000 value. and 'sum_lo' is 0x1 value. it is matched a sum of 0x1_0003 in 'value' column at row 1 and 0xfffe in 'sum_lo' at row 0.
we may strict a number more than or equal '2^16' in 'value' column. In here, we used more than '2^16' for testing.

- Overflow case
    | - | value | sum_overflow_inv | sum_overflow | sum_hi(x * 2^16)  | sum_lo(x * 2^0) | instance  |
    | - | - | - | - | - | - | - |
    | 0 | - | - | - |  0 |  0xfffe | 0 |
    | 1 | 0x1_0000_0002 | * | 0x1 |  0x1 | 0x1 | 0xffff |
    | 2 | - | - | - | - | - | 0x1 |
    | 3 | - | - | - | - | - | 0x1 |
    | 4 | - | - | - | - | - | 0x1 |

In this case, addition value is more than 2^32. so, the circuit got panic with this input due to 'is_zero' chip.

# Experiment 16 - Overflow Check V2

The `overflow_check_v2` chip is designed to provide a more robust mechanism for checking overflow conditions in computations.

The `overflow_check_v2` chip accomplishes this by decomposing the values in cells, which allows it to handle larger numbers. In other words, instead of storing a large number in a single cell, it breaks down the number into smaller parts and stores each part in a separate cell. This method enables the circuit to handle much larger numbers than would be possible with a single cell.

The primary purpose of this chip is to verify the equality between the original value and its decomposed counterpart. By doing this, the chip can ensure that the decomposed values correctly represent the original value and that no overflow has occurred during computations.

However, while the chip can handle larger numbers by decomposing them into smaller parts, it's important to note that it can't handle values that are larger than the prime number of the finite field. This is a fundamental limit of the chip and the underlying circuit.

For better understanding, let's consider a scenario where we check for overflow in three steps, 'a', 'b', and 'a + b', at the circuit level. Assume that the prime number of the finite field is 255, 'a' is 42, and 'b' is 221. It's easy to see that both 'a' and 'b' are valid and don't overflow. However, 'a + b' equals 262, which is over the prime number. Thus, the chip will only return the result as 7 (262 mod 255), not 262, because it's over the modulus.


The key feature is in [here](https://github.com/summa-dev/halo2-experiments/blob/7c4f08a50be277c8b49b3d81eebc3cd314c5e1c7/src/circuits/overflow_check_v2.rs#L50-L56) `overflow_check_v2` circuit 

```Rust
// check overflow
        chip.assign(layouter.namespace(|| "checking overflow value a"), self.a)?;
        chip.assign(layouter.namespace(|| "checking overflow value b"), self.b)?;
        chip.assign(layouter.namespace(|| "checking overflow value a + b"), self.a + self.b,)?;
```

Note that those 'a' and 'b' are `bigInt` type. So, we do not worry about overflowing when add it before using the input variable to `assign` method. 

# Experiment 17 - Safe Accumulator

The safe_accumulator is a chip designed to accumulate values within a circuit and effectively manage the risk of overflow. Its main purpose is to maintain an accumulated total of values that could potentially be larger than the modulus of the finite field in the circuit.

It achieves this by breaking down the total value into smaller parts and storing each part in a separate cell. This allows the chip to effectively handle much larger numbers than would be possible with a single cell.

Now, let's dive into the structure of the safe_accumulator config in more detail.

```Rust
pub struct SafeAccumulatorConfig<const MAX_BITS: u8, const ACC_COLS: usize> {
    pub update_value: Column<Advice>,
    pub left_most_inv: Column<Advice>,
    pub add_carries: [Column<Advice>; ACC_COLS],
    pub accumulate: [Column<Advice>; ACC_COLS],
    pub instance: Column<Instance>,
    pub is_zero: IsZeroConfig,
    pub selector: [Selector; 2],
}
```

The chip incorporates a mechanism to check for overflow, utilizing the leftmost accumulate column for this purpose. Consequently, you need to configure one additional column beyond the maximum accumulation value. For instance, if you're checking values beyond 64 bits (8 bytes), you should configure 9 columns in the circuit, with MAX_BITS set to 8. Alternatively, you can set MAX_BITS to 16 and use 5 columns, given that 16 * 4 equals 64 bits. To prevent malicious computations on the leftmost accumulate column, constraints for other accumulate columns are put in place, similar to the mechanism used in the add_carry_v1 chip.

The chip has constraints that the accumulated values fall within a predefined range. It also ensures that the carry values are binary. These features work together to prevent overflow and maintain the integrity of the accumulated total.

A unique advantage of the safe_accumulator over some other chips (like `add_carry_v1`) is that it can handle numbers larger than the modular limit of the finite fields in the circuit. This makes it particularly useful in scenarios where we need to deal with large numbers that might exceed the field modulus.

However, this chip is experimental and has limitations. The values added to the accumulator are limited by `MAX_BITS` and might need decomposition for handling larger values.
