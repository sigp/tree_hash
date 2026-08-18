//! An empty `active_fields()` list must be rejected.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(struct_behaviour = "progressive_container", active_fields())]
struct Foo {
    a: u8,
}

fn main() {}
