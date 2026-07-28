//! A trailing `0` in `active_fields` must be rejected: the bitvector is canonically delimited by
//! its highest active field, so a trailing zero would change the root rather than being a no-op.
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
#[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 0))]
struct Foo {
    a: u8,
}

fn main() {}
