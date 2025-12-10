use darling::{ast::NestedMeta, Error, FromDeriveInput, FromMeta};
use quote::quote;

pub const MAX_ACTIVE_FIELDS: usize = 256;
pub const ACTIVE_FIELDS_PACKED_BITS_LEN: usize = MAX_ACTIVE_FIELDS / 8;

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

#[derive(Debug, FromMeta)]
pub enum EnumBehaviour {
    Transparent,
    Union,
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
            return Err(Error::custom(format!("active_fields must be non-empty")));
        }
        if active_fields.len() > MAX_ACTIVE_FIELDS {
            return Err(Error::custom(format!(
                "active_fields cannot contain more than {MAX_ACTIVE_FIELDS} entries"
            )));
        }

        if let Some(false) = active_fields.last() {
            return Err(Error::custom(format!(
                "the last entry of active_fields must not be 0"
            )));
        }

        Ok(Self { active_fields })
    }

    pub fn packed(&self) -> [u8; ACTIVE_FIELDS_PACKED_BITS_LEN] {
        let mut result = [0; ACTIVE_FIELDS_PACKED_BITS_LEN];
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
        let packed = self.packed().to_vec();
        quote! {
            [
                #(#packed),*
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
                0b0000001, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0,
            ]
        );

        let active_fields = ActiveFields {
            active_fields: vec![true, false, true, false, false, true],
        };
        assert_eq!(
            active_fields.packed(),
            [
                0b0100101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0,
            ]
        );
    }
}
