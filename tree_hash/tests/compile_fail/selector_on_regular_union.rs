//! Manual selectors are not supported in a regular (non-compatible) union, whose selectors are
//! implied by variant order.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "union")]
enum Foo {
    #[tree_hash(selector = "1")]
    A(u8),
}

fn main() {}
