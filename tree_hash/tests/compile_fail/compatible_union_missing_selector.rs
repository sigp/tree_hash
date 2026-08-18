//! Every variant of a compatible union must carry an explicit selector.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "compatible_union")]
enum Foo {
    #[tree_hash(selector = "1")]
    A(u8),
    B(u64),
}

fn main() {}
