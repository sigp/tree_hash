//! `struct_behaviour` is not valid on an enum.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "union", struct_behaviour = "container")]
enum Foo {
    A(u8),
}

fn main() {}
