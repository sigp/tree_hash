//! A progressive container without `active_fields` must be rejected.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(struct_behaviour = "progressive_container")]
struct Foo {
    a: u8,
}

fn main() {}
