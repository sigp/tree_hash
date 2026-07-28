//! A variant carrying different selectors in its `tree_hash` and `ssz` attributes must be
//! rejected.
use ssz_derive::Encode;
use tree_hash_derive::TreeHash;

#[derive(Encode, TreeHash)]
#[ssz(enum_behaviour = "compatible_union")]
#[tree_hash(enum_behaviour = "compatible_union")]
enum Foo {
    #[ssz(selector = "3")]
    #[tree_hash(selector = "5")]
    A(u8),
}

fn main() {}
