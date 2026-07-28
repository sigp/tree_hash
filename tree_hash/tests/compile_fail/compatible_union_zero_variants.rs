//! A compatible union with no variants must be rejected explicitly.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "compatible_union")]
enum Foo {}

fn main() {}
