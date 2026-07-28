//! More than one variant-level `tree_hash` attribute must be rejected.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "compatible_union")]
enum Foo {
    #[tree_hash(selector = "1")]
    #[tree_hash(selector = "2")]
    A(u8),
}

fn main() {}
