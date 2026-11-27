//! Map-key masking during sensitive producer serialization.
//!
//! Traversal leaves map keys unchanged. Serialization cannot recover their
//! policies, so this adapter replaces every map key with a positional
//! placeholder. Names sent through Serde's struct and variant methods remain
//! visible. Flattened structs and internally tagged newtype maps use the map
//! interface, so their field and tag keys are masked too.

use serde::ser::{
    Error as _, Serialize, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant,
    SerializeTuple, SerializeTupleStruct, SerializeTupleVariant, Serializer,
};

/// Serialize the wrapped value with every map key, at any depth, masked.
pub(super) struct MaskMapKeys<'a, T: ?Sized>(pub(super) &'a T);

impl<T: Serialize + ?Sized> Serialize for MaskMapKeys<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(Masking(serializer))
    }
}

fn masked_key(index: usize) -> String {
    format!("[REDACTED-KEY-{index}]")
}

struct Masking<S>(S);

macro_rules! forward_scalars {
    ($($method:ident($ty:ty)),* $(,)?) => {
        $(
            fn $method(self, value: $ty) -> Result<Self::Ok, Self::Error> {
                self.0.$method(value)
            }
        )*
    };
}

impl<S: Serializer> Serializer for Masking<S> {
    type Ok = S::Ok;
    type Error = S::Error;
    type SerializeSeq = Compound<S::SerializeSeq>;
    type SerializeTuple = Compound<S::SerializeTuple>;
    type SerializeTupleStruct = Compound<S::SerializeTupleStruct>;
    type SerializeTupleVariant = Compound<S::SerializeTupleVariant>;
    type SerializeMap = MaskedMap<S::SerializeMap>;
    type SerializeStruct = MaskedStruct<S>;
    type SerializeStructVariant = Compound<S::SerializeStructVariant>;

    forward_scalars!(
        serialize_bool(bool),
        serialize_i8(i8),
        serialize_i16(i16),
        serialize_i32(i32),
        serialize_i64(i64),
        serialize_i128(i128),
        serialize_u8(u8),
        serialize_u16(u16),
        serialize_u32(u32),
        serialize_u64(u64),
        serialize_u128(u128),
        serialize_f32(f32),
        serialize_f64(f64),
        serialize_char(char),
        serialize_str(&str),
        serialize_bytes(&[u8]),
    );

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_none()
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_some(&MaskMapKeys(value))
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_unit()
    }

    fn serialize_unit_struct(self, name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_unit_struct(name)
    }

    fn serialize_unit_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_unit_variant(name, variant_index, variant)
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_newtype_struct(name, &MaskMapKeys(value))
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.0
            .serialize_newtype_variant(name, variant_index, variant, &MaskMapKeys(value))
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        self.0.serialize_seq(len).map(Compound)
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.0.serialize_tuple(len).map(Compound)
    }

    fn serialize_tuple_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.0.serialize_tuple_struct(name, len).map(Compound)
    }

    fn serialize_tuple_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        self.0
            .serialize_tuple_variant(name, variant_index, variant, len)
            .map(Compound)
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        self.0.serialize_map(len).map(|inner| MaskedMap {
            inner,
            next_index: 0,
        })
    }

    fn serialize_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        if name == RAW_VALUE && *RAW_VALUE_ENABLED {
            Ok(MaskedStruct::Raw {
                target: self.0,
                parsed: None,
            })
        } else {
            self.0.serialize_struct(name, len).map(MaskedStruct::Typed)
        }
    }

    fn serialize_struct_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        self.0
            .serialize_struct_variant(name, variant_index, variant, len)
            .map(Compound)
    }

    fn is_human_readable(&self) -> bool {
        self.0.is_human_readable()
    }
}

struct Compound<C>(C);

impl<C: SerializeSeq> SerializeSeq for Compound<C> {
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.0.serialize_element(&MaskMapKeys(value))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.0.end()
    }
}

impl<C: SerializeTuple> SerializeTuple for Compound<C> {
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.0.serialize_element(&MaskMapKeys(value))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.0.end()
    }
}

impl<C: SerializeTupleStruct> SerializeTupleStruct for Compound<C> {
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.0.serialize_field(&MaskMapKeys(value))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.0.end()
    }
}

impl<C: SerializeTupleVariant> SerializeTupleVariant for Compound<C> {
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.0.serialize_field(&MaskMapKeys(value))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.0.end()
    }
}

// RawValue uses this reserved struct name to pass an unparsed JSON string to
// serde_json. Forwarding it as a normal struct would bypass serialize_map.
const RAW_VALUE: &str = "$serde_json::private::RawValue";

// Cargo can enable serde_json/raw_value through any consumer. With it off,
// the same name is an ordinary Serde struct and its typed fields must survive.
static RAW_VALUE_ENABLED: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
    read_raw_field(RAW_VALUE, "null").is_ok_and(|probe| probe.is_null())
});

fn read_raw_field<T: Serialize + ?Sized>(
    key: &'static str,
    value: &T,
) -> serde_json::Result<serde_json::Value> {
    let mut raw = serde_json::value::Serializer.serialize_struct(RAW_VALUE, 1)?;
    raw.serialize_field(key, value)?;
    SerializeStruct::end(raw)
}

enum MaskedStruct<S: Serializer> {
    Typed(S::SerializeStruct),
    Raw {
        target: S,
        parsed: Option<serde_json::Value>,
    },
}

impl<S: Serializer> SerializeStruct for MaskedStruct<S> {
    type Ok = S::Ok;
    type Error = S::Error;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        match self {
            Self::Typed(fields) => fields.serialize_field(key, &MaskMapKeys(value)),
            Self::Raw { parsed, .. } => {
                if parsed.is_some() {
                    return Err(S::Error::custom("duplicate raw JSON field"));
                }
                // Let serde_json validate its own raw field and parse it once.
                *parsed = Some(read_raw_field(key, value).map_err(S::Error::custom)?);
                Ok(())
            }
        }
    }

    fn skip_field(&mut self, key: &'static str) -> Result<(), Self::Error> {
        match self {
            Self::Typed(fields) => fields.skip_field(key),
            Self::Raw { .. } => Ok(()),
        }
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        match self {
            Self::Typed(fields) => fields.end(),
            Self::Raw { target, parsed } => {
                let value = parsed.ok_or_else(|| S::Error::custom("missing raw JSON field"))?;
                MaskMapKeys(&value).serialize(target)
            }
        }
    }
}

impl<C: SerializeStructVariant> SerializeStructVariant for Compound<C> {
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.0.serialize_field(key, &MaskMapKeys(value))
    }

    fn skip_field(&mut self, key: &'static str) -> Result<(), Self::Error> {
        self.0.skip_field(key)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.0.end()
    }
}

struct MaskedMap<C> {
    inner: C,
    next_index: usize,
}

impl<C: SerializeMap> SerializeMap for MaskedMap<C> {
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, _key: &T) -> Result<(), Self::Error> {
        let key = masked_key(self.next_index);
        self.next_index += 1;
        self.inner.serialize_key(&key)
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.inner.serialize_value(&MaskMapKeys(value))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.inner.end()
    }
}
