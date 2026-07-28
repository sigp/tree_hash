//! Enum variants must have exactly one unnamed (tuple) field: named fields are rejected with a
//! clear message rather than a confusing error in the generated match patterns.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "union")]
enum Foo {
    A { x: u8 },
}

fn main() {}
