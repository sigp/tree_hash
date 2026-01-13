#![recursion_limit = "256"]
mod attrs;

use crate::attrs::{EnumBehaviour, StructBehaviour, StructOpts, VariantOpts};
use darling::{FromDeriveInput, FromMeta};
use proc_macro::TokenStream;
use quote::quote;
use std::convert::TryInto;
use syn::{parse_macro_input, Attribute, DataEnum, DataStruct, DeriveInput, Ident};

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
        is_tree_hash_attr(attr) && attr.parse_args::<Ident>().unwrap() == "skip_hashing"
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
                EnumBehaviour::Union | EnumBehaviour::CompatibleUnion => {
                    tree_hash_derive_enum_union(&item, s, enum_behaviour)
                }
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

    // Compute the field hashes while accounting for inactive fields which hash as 0x0.
    //
    // The `mixin_logic` is the expression to mix in the `active_fields` in the case of a
    // progressive container.
    let (field_hashes, mixin_logic) =
        if let StructBehaviour::ProgressiveContainer = struct_behaviour {
            let Some(active_fields) = active_fields_opt else {
                panic!("active_fields must be provided for progressive_container");
            };

            let mut active_field_index = 0;
            let mut field_hashes: Vec<proc_macro2::TokenStream> = vec![];
            for active in &active_fields.active_fields {
                if *active {
                    let Some(ident) = idents.get(active_field_index) else {
                        panic!(
                            "active_fields is inconsistent with struct fields. \
                             index: {active_field_index}, hashable fields: {}",
                            idents.len()
                        )
                    };
                    active_field_index += 1;
                    field_hashes.push(quote! { self.#ident.tree_hash_root() });
                } else {
                    field_hashes.push(quote! { tree_hash::Hash256::ZERO });
                }
            }

            let packed_active_fields = active_fields.packed_tokens();

            let mixin_logic = quote! {
                const ACTIVE_FIELDS: [u8; 32] = #packed_active_fields;
                tree_hash::mix_in_active_fields(container_root, ACTIVE_FIELDS)
            };

            (field_hashes, mixin_logic)
        } else {
            (
                idents
                    .into_iter()
                    .map(|ident| quote! { self.#ident.tree_hash_root() })
                    .collect(),
                quote! { container_root },
            )
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
                    hasher.write(#field_hashes.as_slice())
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

/// Derive `TreeHash` for an `enum` following the compatible union or ordinary union SSZ spec.
///
/// The union selectors for a compatible union MUST be defined using the variant attribute:
///
/// - `tree_hash(selector = "X")`
///
/// The union selectors for an ordinary union will be determined based upon the order in which the
/// enum variants are defined. E.g., the top-most variant in the enum will have a selector of `0`,
/// the variant beneath it will have a selector of `1` and so on.
///
/// # Limitations
///
/// Only supports enums where each variant has a single field.
fn tree_hash_derive_enum_union(
    derive_input: &DeriveInput,
    enum_data: &DataEnum,
    enum_behaviour: EnumBehaviour,
) -> TokenStream {
    let name = &derive_input.ident;
    let (impl_generics, ty_generics, where_clause) = &derive_input.generics.split_for_impl();

    // Parse variant-level configuration.
    let variant_opts = parse_variant_opts(enum_data);

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

    let union_selectors = match enum_behaviour {
        EnumBehaviour::CompatibleUnion => get_compatible_union_selectors(enum_data, &variant_opts),
        EnumBehaviour::Union => {
            // For now we don't allow selectors in ordinary unions to be set manually.
            assert!(
                variant_opts.iter().all(|opt| opt.selector.is_none()),
                "specifying the selector in a regular union is not supported"
            );
            compute_union_selectors(patterns.len())
        }
        EnumBehaviour::Transparent => unreachable!("union code called for transparent enum"),
    };

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

fn parse_variant_opts(enum_data: &DataEnum) -> Vec<VariantOpts> {
    enum_data
        .variants
        .iter()
        .map(|variant| {
            let tree_hash_attrs = variant
                .attrs
                .iter()
                .filter(|attr| is_tree_hash_attr(attr))
                .collect::<Vec<_>>();
            let ssz_attrs = variant
                .attrs
                .iter()
                .filter(|attr| is_ssz_attr(attr))
                .collect::<Vec<_>>();

            // Check for duplicate `tree_hash` attributes.
            // Checking duplicate `ssz` attributes is the job of the `ssz_derive` macro.
            if tree_hash_attrs.len() > 1 {
                panic!("more than one variant-level \"tree_hash\" attribute provided");
            }

            let tree_hash_opts = tree_hash_attrs
                .first()
                .map(|attr| VariantOpts::from_meta(&attr.meta).unwrap());

            let ssz_opts = ssz_attrs
                .first()
                .map(|attr| VariantOpts::from_meta(&attr.meta).unwrap());

            // Check consistency with SSZ opts, or fall back to SSZ attribute if tree_hash attribute
            // is absent.
            match (tree_hash_opts, ssz_opts) {
                (Some(tree_hash), Some(ssz)) => {
                    assert_eq!(
                        tree_hash, ssz,
                        "inconsistent \"tree_hash\" and \"ssz\" attributes"
                    );
                    tree_hash
                }
                (Some(attr), None) | (None, Some(attr)) => attr,
                (None, None) => VariantOpts::default(),
            }
        })
        .collect()
}

/// Predicate for determining whether an attribute is a `tree_hash` attribute.
fn is_tree_hash_attr(attr: &Attribute) -> bool {
    is_attr_with_ident(attr, "tree_hash")
}

fn is_ssz_attr(attr: &Attribute) -> bool {
    is_attr_with_ident(attr, "ssz")
}

/// Predicate for determining whether an attribute has the given `ident` as its path.
fn is_attr_with_ident(attr: &Attribute, ident: &str) -> bool {
    attr.path()
        .get_ident()
        .is_some_and(|attr_ident| *attr_ident == ident)
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

fn get_compatible_union_selectors(enum_data: &DataEnum, variant_opts: &[VariantOpts]) -> Vec<u8> {
    enum_data
        .variants
        .iter()
        .zip(variant_opts.iter())
        .map(|(variant, variant_opt)| {
            let variant_name = &variant.ident;
            let Some(selector) = variant_opt.selector else {
                panic!("you must define a selector for variant \"{variant_name}\"");
            };
            if selector == 0 || selector > MAX_UNION_SELECTOR {
                panic!(
                    "selector = {selector} for variant \"{variant_name}\" is illegal in a \
                     compatible union"
                );
            }
            selector
        })
        .collect()
}
