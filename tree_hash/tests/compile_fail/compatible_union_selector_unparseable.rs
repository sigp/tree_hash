//! A selector that does not fit in a `u8` fails at attribute parsing (with a less specific
//! message than the in-range-but-illegal cases).
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "compatible_union")]
enum Foo {
    #[tree_hash(selector = "300")]
    A(u8),
}

fn main() {}
