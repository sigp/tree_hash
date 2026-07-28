//! `active_fields` is not valid on an enum.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "union", active_fields(1))]
enum Foo {
    A(u8),
}

fn main() {}
