//! `enum_behaviour` is not valid on a struct.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "transparent")]
struct Foo {
    a: u8,
}

fn main() {}
