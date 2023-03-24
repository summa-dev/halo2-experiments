# halo2-experiments

For practice to using halo2

This library makes use of the [PSE Fork of Halo2](https://github.com/privacy-scaling-explorations/halo2) and the related [Halo2 Curves](https://github.com/privacy-scaling-explorations/halo2curves).

List of available experiments: 

- [Experiment 1 - Inclusion Check](#experiment-1---inclusion-check)
- [Experiment 2 - Inclusion Check V2](#experiment-2---inclusion-check-v2)
- [Experiment 3 - Dummy Hash V1](#experiment-3---dummy-hash-v1)
- [Experiment 4 - Dummy Hash V2](#experiment-4---dummy-hash-v2)
- [Experiment 5 - Merkle Tree V1](#experiment-5---merkle-tree-v1)


# Experiment 1 - Inclusion Check

The inclusion check circuit is a circuit built using 2 advise columns, 1 selector column and 1 instance column. The advise columns contain the list of usernames and balances. The instance column contains the username and balance of the user that I am generating the proof for. Let's call it `pubUsername` and `pubBalance` This should be public and the snark should verify that there's a row in the advise column where `pubUsername` and `pubBalance` entries match. At that row the selector should be turned on.

| username  | balance  |instance  |
| ----      | ---      |        --- |
| 12332 | 200 | 56677
| 56677 | 100 | 100
| 45563 | 700 | 

The constraint is enforced as a permutation check between the cell of the advise column and the cell of the instance column.

In this example, we don't really need a selector as we are not enforcing any custom gate.

`cargo test -- --nocapture test_inclusion_check_1`
`cargo test --all-features -- --nocapture print_inclusion_check` 

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

`cargo test -- --nocapture test_hash_2`

# Experiment 5 - Merkle Tree V1

Experiment of a merkle tree from [`halo2-merkle-tree`](https://github.com/jtguibas/halo2-merkle-tree/blob/main/src/chips/hash_2.rs).

The dummy hash function for the merkle tree is `a + b = c`. 

The circuit is made of 3 advice columns `a`, `b` and `c`, 3 selector columns `bool_selector`, `swap_selector` and `hash_selector` and 1 instance column `instance`.

The input passed to instantiate a circuit are the `leaf` the we are trying to prove the inclusion of in the tree, `path_elements` which is an array of the siblings of the leaf and `path_indices` which is an array of bits indicating the relative position of the node that we are performing the hashing on to its sibilings (`path_elements`). For example a path index of `1` means that the sibling is on the left of its node, while a path index of `0` means that the sibling is on the right of its node. Therefore the hashing needs to be performed in a specific order. Note that considering our dummy hash, the order of the hashing is not important as the result is the same. But this will be important when implementing a real hash function.

The assignment of the values to the columns is performed using a region that covers 2 rows:

| a           | b                | c       | bool_selector | swap_selector | hash_selector
| --          | -                | --      |    --         | ---           | ---
| leaf        | path_element     | index   |     1         | 1             | 0
| input left  | input right      | digest  |     0         | 0             | 1

At row 0, we assign the leaf, the element (from `path_element`) and the bit (from `path_indices`). At this row we turn on `bool_selector` and `swap_selector`. 

At row 1, we assign the input left, the input right and the digest. At this row we turn on `hash_selector`.

The circuit contains 3 custom gates: 

- If the `bool_selector` is on, checks that the value inside the c column is either 0 or 1
- If the `swap_selector` is on, checks that the swap on the next row is performed correctly according to the `bit`
- If the `hash_selector` is on, checks that the digest is equal to the (dummy) hash between input left and input right

Furthermore, the circuit contains 2 permutation check:

- Verifies that the last `digest` of the circuit is equal to the `root` of the tree which is passed as (public) value to the instance column

`cargo test -- --nocapture test_merkle_tree_1`

# Experiment 6 - Merkle Tree V2

This Merkle Tree specification works exactly the same as the previous one. The only difference is that it makes use of the `Hash2Chip` and `Hash2Config` created in experiment 4 rather than rewriting the logic of the hash inside the Circuit, as it was done in experiment 5.

TO DO: 
- [ ] Replace usage of constants in Inclusion Check.
- [ ] Verifies that the leaf used inside the circuit is equal to the `leaf` passed as (public) value to the instance column




