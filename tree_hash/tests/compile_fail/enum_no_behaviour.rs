//! An enum without an `enum_behaviour` attribute must be rejected with a message that names the
//! missing attribute and its accepted values.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
enum NoBehaviour {
    A(u8),
    B(u64),
}

fn main() {}
