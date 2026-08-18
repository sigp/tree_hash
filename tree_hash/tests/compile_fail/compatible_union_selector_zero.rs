//! Selector 0 is illegal in a compatible union.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "compatible_union")]
enum Foo {
    #[tree_hash(selector = "0")]
    A(u8),
}

fn main() {}
