//! `active_fields` entries must be `0` or `1`.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 2))]
struct Foo {
    a: u8,
    b: u8,
}

fn main() {}
