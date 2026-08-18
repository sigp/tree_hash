//! A transparent enum never mixes in a selector, so specifying one must be rejected rather than
//! silently ignored.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "transparent")]
enum Foo {
    #[tree_hash(selector = "1")]
    A(u8),
}

fn main() {}
