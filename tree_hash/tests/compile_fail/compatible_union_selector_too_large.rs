//! Selectors above 127 are reserved and illegal in a compatible union.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "compatible_union")]
enum Foo {
    #[tree_hash(selector = "128")]
    A(u8),
}

fn main() {}
