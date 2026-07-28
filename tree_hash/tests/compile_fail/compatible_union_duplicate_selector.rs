//! Duplicate selectors in a compatible union must be rejected.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "compatible_union")]
enum Foo {
    #[tree_hash(selector = "1")]
    A(u8),
    #[tree_hash(selector = "1")]
    B(u64),
}

fn main() {}
