//! Enum variants must have exactly one unnamed field: a two-field tuple variant is rejected.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "transparent")]
enum Foo {
    A(u8, u64),
}

fn main() {}
