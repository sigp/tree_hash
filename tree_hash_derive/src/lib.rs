#![recursion_limit = "256"]
mod attrs;

use crate::attrs::{EnumBehaviour, StructBehaviour, StructOpts};
use darling::FromDeriveInput;
use proc_macro::TokenStream;
use quote::quote;
use std::convert::TryInto;
use syn::{parse_macro_input, DataEnum, DataStruct, DeriveInput, Ident};

/// The highest possible union selector value (higher values are reserved for backwards compatible
/// extensions).
const MAX_UNION_SELECTOR: u8 = 127;

/// Return a Vec of `syn::Ident` for each named field in the struct, whilst filtering out fields
/// that should not be hashed.
///
/// # Panics
/// Any unnamed struct field (like in a tuple struct) will raise a panic at compile time.
fn get_hashable_fields(struct_data: &syn::DataStruct) -> Vec<&syn::Ident> {
    get_hashable_fields_and_their_caches(struct_data)
        .into_iter()
        .map(|(ident, _)| ident)
        .collect()
}

/// Return a Vec of the hashable fields of a struct, and each field's type and optional cache field.
fn get_hashable_fields_and_their_caches(
    struct_data: &syn::DataStruct,
) -> Vec<(&syn::Ident, syn::Type)> {
    struct_data
        .fields
        .iter()
        .filter_map(|f| {
            if should_skip_hashing(f) {
                None
            } else {
                let ident = f
                    .ident
                    .as_ref()
                    .expect("tree_hash_derive only supports named struct fields");
                Some((ident, f.ty.clone()))
            }
        })
        .collect()
}

/// Returns true if some field has an attribute declaring it should not be hashed.
///
/// The field attribute is: `#[tree_hash(skip_hashing)]`
fn should_skip_hashing(field: &syn::Field) -> bool {
    field.attrs.iter().any(|attr| {
        attr.path().is_ident("tree_hash") && attr.parse_args::<Ident>().unwrap() == "skip_hashing"
    })
}

/// Implements `tree_hash::TreeHash` for a type.
///
/// Fields are hashed in the order they are defined.
#[proc_macro_derive(TreeHash, attributes(tree_hash))]
pub fn tree_hash_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);
    let opts = StructOpts::from_derive_input(&item).unwrap();
    let enum_opt = opts.enum_behaviour;
    let struct_opt = opts.struct_behaviour;

    match (&item.data, enum_opt, struct_opt) {
        (syn::Data::Struct(s), enum_opt, struct_opt) => {
            if enum_opt.is_some() {
                panic!("enum_behaviour is invalid for structs");
            }
            let struct_behaviour = struct_opt.unwrap_or_default();
            tree_hash_derive_struct(&item, s, struct_behaviour, opts.active_fields)
        }
        (syn::Data::Enum(s), Some(enum_behaviour), struct_opt) => {
            if struct_opt.is_some() {
                panic!("struct_behaviour is invalid for enums");
            }
            match enum_behaviour {
                EnumBehaviour::Transparent => tree_hash_derive_enum_transparent(&item, s),
                EnumBehaviour::Union => tree_hash_derive_enum_union(&item, s),
            }
        }
        _ => panic!("tree_hash_derive only supports structs and enums"),
    }
}

fn tree_hash_derive_struct(
    item: &DeriveInput,
    struct_data: &DataStruct,
    struct_behaviour: StructBehaviour,
    active_fields_opt: Option<attrs::ActiveFields>,
) -> TokenStream {
    let name = &item.ident;
    let (impl_generics, ty_generics, where_clause) = &item.generics.split_for_impl();

    let idents = get_hashable_fields(struct_data);

    let hasher_init = if let StructBehaviour::ProgressiveContainer = struct_behaviour {
        quote! { tree_hash::ProgressiveMerkleHasher::new() }
    } else {
        let num_leaves = idents.len();
        quote! { tree_hash::MerkleHasher::with_leaves(#num_leaves) }
    };
    let mixin_logic = if let StructBehaviour::ProgressiveContainer = struct_behaviour {
        let Some(active_fields) = active_fields_opt else {
            panic!("active_fields must be provided for progressive_container");
        };

        let packed_active_fields = active_fields.packed_tokens();

        quote! {
            const ACTIVE_FIELDS: [u8; 32] = #packed_active_fields;
            tree_hash::mix_in_active_fields(container_root, ACTIVE_FIELDS)
        }
    } else {
        quote! { container_root }
    };

    let output = quote! {
        impl #impl_generics tree_hash::TreeHash for #name #ty_generics #where_clause {
            fn tree_hash_type() -> tree_hash::TreeHashType {
                // FIXME(sproul): consider adjusting this with active_fields
                tree_hash::TreeHashType::Container
            }

            fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
                unreachable!("Struct should never be packed.")
            }

            fn tree_hash_packing_factor() -> usize {
                unreachable!("Struct should never be packed.")
            }

            fn tree_hash_root(&self) -> tree_hash::Hash256 {
                let mut hasher = #hasher_init;

                #(
                    hasher.write(self.#idents.tree_hash_root().as_slice())
                        .expect("tree hash derive should not apply too many leaves");
                )*

                let container_root = hasher.finish().expect("tree hash derive should not have a remaining buffer");

                #mixin_logic
            }
        }
    };
    output.into()
}

/// Derive `TreeHash` for an enum in the "transparent" method.
///
/// The "transparent" method is distinct from the "union" method specified in the SSZ specification.
/// When using "transparent", the enum will be ignored and the contained field will be hashed as if
/// the enum does not exist.
///
///## Limitations
///
/// Only supports:
/// - Enums with a single field per variant, where
///     - All fields are "container" types.
///
/// ## Panics
///
/// Will panic at compile-time if the single field requirement isn't met, but will panic *at run
/// time* if the container type requirement isn't met.
fn tree_hash_derive_enum_transparent(
    derive_input: &DeriveInput,
    enum_data: &DataEnum,
) -> TokenStream {
    let name = &derive_input.ident;
    let (impl_generics, ty_generics, where_clause) = &derive_input.generics.split_for_impl();

    let (patterns, type_exprs): (Vec<_>, Vec<_>) = enum_data
        .variants
        .iter()
        .map(|variant| {
            let variant_name = &variant.ident;

            if variant.fields.len() != 1 {
                panic!("TreeHash can only be derived for enums with 1 field per variant");
            }

            let pattern = quote! {
                #name::#variant_name(ref inner)
            };

            let ty = &(&variant.fields).into_iter().next().unwrap().ty;
            let type_expr = quote! {
                <#ty as tree_hash::TreeHash>::tree_hash_type()
            };
            (pattern, type_expr)
        })
        .unzip();

    let output = quote! {
        impl #impl_generics tree_hash::TreeHash for #name #ty_generics #where_clause {
            fn tree_hash_type() -> tree_hash::TreeHashType {
                #(
                    assert_eq!(
                        #type_exprs,
                        tree_hash::TreeHashType::Container,
                        "all variants must be of container type"
                    );
                )*
                tree_hash::TreeHashType::Container
            }

            fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
                unreachable!("Enum should never be packed")
            }

            fn tree_hash_packing_factor() -> usize {
                unreachable!("Enum should never be packed")
            }

            fn tree_hash_root(&self) -> tree_hash::Hash256 {
                match self {
                    #(
                        #patterns => inner.tree_hash_root(),
                    )*
                }
            }
        }
    };
    output.into()
}

/// Derive `TreeHash` for an `enum` following the "union" SSZ spec.
///
/// The union selector will be determined based upon the order in which the enum variants are
/// defined. E.g., the top-most variant in the enum will have a selector of `0`, the variant
/// beneath it will have a selector of `1` and so on.
///
/// # Limitations
///
/// Only supports enums where each variant has a single field.
fn tree_hash_derive_enum_union(derive_input: &DeriveInput, enum_data: &DataEnum) -> TokenStream {
    let name = &derive_input.ident;
    let (impl_generics, ty_generics, where_clause) = &derive_input.generics.split_for_impl();

    let patterns: Vec<_> = enum_data
        .variants
        .iter()
        .map(|variant| {
            let variant_name = &variant.ident;

            if variant.fields.len() != 1 {
                panic!("TreeHash can only be derived for enums with 1 field per variant");
            }

            quote! {
                #name::#variant_name(ref inner)
            }
        })
        .collect();

    let union_selectors = compute_union_selectors(patterns.len());

    let output = quote! {
        impl #impl_generics tree_hash::TreeHash for #name #ty_generics #where_clause {
            fn tree_hash_type() -> tree_hash::TreeHashType {
                tree_hash::TreeHashType::Container
            }

            fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
                unreachable!("Enum should never be packed")
            }

            fn tree_hash_packing_factor() -> usize {
                unreachable!("Enum should never be packed")
            }

            fn tree_hash_root(&self) -> tree_hash::Hash256 {
                match self {
                    #(
                        #patterns => {
                            let root = inner.tree_hash_root();
                            let selector = #union_selectors;
                            tree_hash::mix_in_selector(&root, selector)
                                .expect("derive macro should prevent out-of-bounds selectors")
                        },
                    )*
                }
            }
        }
    };
    output.into()
}

fn compute_union_selectors(num_variants: usize) -> Vec<u8> {
    let union_selectors = (0..num_variants)
        .map(|i| {
            i.try_into()
                .expect("union selector exceeds u8::max_value, union has too many variants")
        })
        .collect::<Vec<u8>>();

    let highest_selector = union_selectors
        .last()
        .copied()
        .expect("0-variant union is not permitted");

    assert!(
        highest_selector <= MAX_UNION_SELECTOR,
        "union selector {} exceeds limit of {}, enum has too many variants",
        highest_selector,
        MAX_UNION_SELECTOR
    );

    union_selectors
}
