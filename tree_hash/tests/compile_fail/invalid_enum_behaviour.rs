//! An unknown `enum_behaviour` value must be rejected.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "transprent")]
enum Foo {
    A(u8),
}

fn main() {}
