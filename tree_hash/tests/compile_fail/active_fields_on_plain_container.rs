//! `active_fields` is only valid with `struct_behaviour = "progressive_container"`.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(active_fields(1))]
struct Foo {
    a: u8,
}

fn main() {}
