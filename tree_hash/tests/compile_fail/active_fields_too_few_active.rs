//! An under-specified `active_fields` (fewer active entries than hashable fields) must be
//! rejected, otherwise trailing fields would be silently dropped from the hash.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(struct_behaviour = "progressive_container", active_fields(1))]
struct Foo {
    a: u8,
    b: u8,
}

fn main() {}
