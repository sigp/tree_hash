use darling::{ast::NestedMeta, Error, FromDeriveInput, FromMeta};
use quote::quote;

pub const MAX_ACTIVE_FIELDS: usize = 256;
/// The number of bytes in the packed `active_fields` bitvector.
///
/// `active_fields` is restricted to `MAX_ACTIVE_FIELDS` (256) bits so that it packs into exactly
/// one 32-byte chunk, which must equal `tree_hash::BYTES_PER_CHUNK` (the generated code asserts
/// this at compile time).
pub const ACTIVE_FIELDS_PACKED_BYTES_LEN: usize = MAX_ACTIVE_FIELDS / 8;

#[derive(Debug, FromDeriveInput)]
#[darling(attributes(tree_hash))]
pub struct StructOpts {
    #[darling(default)]
    pub enum_behaviour: Option<EnumBehaviour>,
    #[darling(default)]
    pub struct_behaviour: Option<StructBehaviour>,
    #[darling(default)]
    pub active_fields: Option<ActiveFields>,
}

/// Variant-level configuration (for enums).
///
/// These attributes NEED to be kept in sync with `ethereum_ssz` because both crates try to read
/// each others attributes to avoid mandatory duplication. In future this might mean parsing some
/// SSZ-only attributes here and then ignoring them.
#[derive(Debug, Default, PartialEq, FromMeta)]
// `allow_unknown_fields` ensures that `ssz`-only keys (current or future) on a shared variant
// attribute are tolerated and ignored here, rather than causing a parse error. This mirrors
// `ssz_derive`'s `VariantOpts`, which tolerates `tree_hash`-only keys for the same reason.
#[darling(allow_unknown_fields)]
pub struct VariantOpts {
    #[darling(default)]
    pub selector: Option<u8>,
}

#[derive(Debug, FromMeta)]
pub enum EnumBehaviour {
    Transparent,
    Union,
    CompatibleUnion,
}

#[derive(Debug, Default, FromMeta)]
pub enum StructBehaviour {
    #[default]
    Container,
    ProgressiveContainer,
}

#[derive(Debug)]
pub struct ActiveFields {
    pub active_fields: Vec<bool>,
}

impl FromMeta for ActiveFields {
    fn from_list(items: &[NestedMeta]) -> Result<Self, Error> {
        let active_fields = items
            .iter()
            .map(|nested_meta| match u8::from_nested_meta(nested_meta) {
                Ok(0) => Ok(false),
                Ok(1) => Ok(true),
                Ok(n) => Err(Error::custom(format!(
                    "invalid integer in active_fields: {n}"
                ))),
                Err(e) => Err(Error::custom(format!(
                    "unable to parse active_fields entry: {e:?}"
                ))),
            })
            .collect::<Result<_, _>>()?;
        Self::new(active_fields)
    }
}

impl ActiveFields {
    fn new(active_fields: Vec<bool>) -> Result<Self, Error> {
        if active_fields.is_empty() {
            return Err(Error::custom("active_fields must be non-empty".to_string()));
        }
        if active_fields.len() > MAX_ACTIVE_FIELDS {
            return Err(Error::custom(format!(
                "active_fields cannot contain more than {MAX_ACTIVE_FIELDS} entries"
            )));
        }

        // A trailing inactive field is materialized as a real zero leaf, so it would change the
        // root rather than being a no-op. The progressive container's `active_fields` bitvector is
        // canonically delimited by its highest active field, so a trailing `0` is not permitted.
        if let Some(false) = active_fields.last() {
            return Err(Error::custom(
                "the last entry of active_fields must not be 0 (the bitvector is delimited by the \
                 highest active field)"
                    .to_string(),
            ));
        }

        Ok(Self { active_fields })
    }

    pub fn packed(&self) -> [u8; ACTIVE_FIELDS_PACKED_BYTES_LEN] {
        let mut result = [0; ACTIVE_FIELDS_PACKED_BYTES_LEN];
        for (i, bit) in self.active_fields.iter().enumerate() {
            if *bit {
                result[i / 8] |= 1 << (i % 8);
            }
        }
        result
    }

    /// Return tokens for the packed representation of these `active_fields`.
    ///
    /// We compute the packed representation at compile-time, and then inline it via the output
    /// of this function.
    pub fn packed_tokens(&self) -> proc_macro2::TokenStream {
        let packed = self.packed();
        let bytes = packed.iter();
        quote! {
            [
                #(#bytes),*
            ]
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn active_fields_packed_basic() {
        let active_fields = ActiveFields {
            active_fields: vec![true],
        };
        assert_eq!(
            active_fields.packed(),
            [
                0b0000_0001,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]
        );

        // Bits are packed LSB-first, so [0, 2, 5] set yields 1 + 4 + 32 = 0b0010_0101.
        let active_fields = ActiveFields {
            active_fields: vec![true, false, true, false, false, true],
        };
        assert_eq!(
            active_fields.packed(),
            [
                0b0010_0101,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]
        );
    }

    #[test]
    fn active_fields_packed_multi_byte() {
        // Bits 0 and 10 set, spanning two bytes: byte 0 has bit 0, byte 1 has bit 2 (10 % 8).
        let mut bits = vec![false; 11];
        bits[0] = true;
        bits[10] = true;
        let packed = ActiveFields::new(bits).unwrap().packed();

        assert_eq!(packed[0], 0b0000_0001);
        assert_eq!(packed[1], 0b0000_0100);
        assert!(packed[2..].iter().all(|&b| b == 0));
    }

    #[test]
    fn active_fields_new_validation() {
        // Empty is rejected.
        assert!(ActiveFields::new(vec![]).is_err());
        // A trailing `0` (inactive last field) is rejected.
        assert!(ActiveFields::new(vec![false]).is_err());
        assert!(ActiveFields::new(vec![true, false]).is_err());
        // More than MAX_ACTIVE_FIELDS entries is rejected.
        assert!(ActiveFields::new(vec![true; MAX_ACTIVE_FIELDS + 1]).is_err());

        // Valid cases.
        assert!(ActiveFields::new(vec![true]).is_ok());
        assert!(ActiveFields::new(vec![false, true]).is_ok());
        assert!(ActiveFields::new(vec![true; MAX_ACTIVE_FIELDS]).is_ok());
    }
}
