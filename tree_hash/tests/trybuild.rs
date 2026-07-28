//! Compile-fail tests for the `#[derive(TreeHash)]` rejection paths.
//!
//! Each file in `tests/compile_fail/` exercises one invalid use of the derive and pins the
//! diagnostic it produces (the `.stderr` file alongside it). These messages are the macro's
//! contract as much as the happy path: if a rejection stops firing, or its message regresses,
//! this suite fails.
//!
//! To regenerate the `.stderr` files after an intentional diagnostic change, run:
//!
//! ```text
//! TRYBUILD=overwrite cargo test --test trybuild
//! ```

#[test]
fn compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
}
