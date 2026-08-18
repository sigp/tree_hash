//! An over-specified `active_fields` (more active entries than hashable fields) must be rejected.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 1, 1))]
struct Foo {
    a: u8,
    b: u8,
}

fn main() {}
