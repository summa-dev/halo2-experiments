# halo2-experiments
For practice to using halo2

# Experiment 1 - Inclusion Check

The inclusion check circuit is a circuit built using 2 advise columns, 1 selector column and 1 instance column. The advise columns contain the list of usernames and balances. The instance column contains the username and balance of the user that I am generating the proof for. Let's call it `pubUsername` and `pubBalance` This should be public and the snark should verify that there's a row in the advise column where `pubUsername` and `pubBalance` entries match. At that row the selector should be turned on.

| username  | balance  |instance  |
| ----      | ---      |        --- |
| 12332 | 200 | 56677
| 56677 | 100 | 100
| 45563 | 700 | 

The constraint is enforced as a permutation check between the cell of the advise column and the cell of the instance column.

In this example, we don't really need a selector as we are not enforcing any custom gate.

`cargo test -- --nocapture test_inclusion_check`
`cargo test --all-features -- --nocapture print_inclusion_check` 

Q: What is PhantomData?

A: In Rust, std::{marker::PhantomData} is a struct that has no fields and is used to indicate to the compiler that a type parameter or a generic type argument is being used in the code, even though it doesn't appear directly in any of the struct's fields or methods. An example of that can be found => https://github.com/enricobottazzi/halo2-fibonacci-ex/blob/master/src/bin/example3.rs#L137 or inside the `InclusionCheckChip` struct in the inclusion_check example

Q: How do you define the InclusionCheckChip struct?

A: In Rust, when you define a struct with a type parameter, such as `InclusionCheckChip<F>`, you are creating a generic struct that can work with any type that satisfies certain constraints. In this case, the type parameter F has a constraint : Field, which means that F must implement the Field trait.

# Experiment 2 - Inclusion Check V2

| username  | balance  | usernameAcc | balanceAcc|selector  | instance  |
| ----      | ---      |   ---     |       --- | -- | --| 
| - | - |  0 | 0 | -  | 56677
| 12332 | 200 |  0 | 0 |  0  | 100
| 56677 | 100 |  56677| 100 | 1  | -
| 45563 | 700 |  56677| 100| 0  | -

The constraint is enforced as a permutation check between the cell of the advise column and the cell of the instance column. In this example:

- We need to use the selector to be turned on on the required line to enforce the custom gate
- The permutation check is enforced between the last row of the `usernameAcc` and `balanceAcc` columns and the instance column values