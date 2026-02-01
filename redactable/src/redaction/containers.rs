//! RedactableContainer implementations for standard library types.
//!
//! This module provides `RedactableContainer` implementations for common std
//! containers (`Option`, `Vec`, `Box`, maps, sets). When walking into these
//! containers, they recursively apply redaction to their contents.
//!
//! ## Map Keys Are Not Redacted
//!
//! For map containers (`HashMap`, `BTreeMap`), only **values** are redacted.
//! Keys are left untouched by design to preserve hashing/ordering invariants.
//! Do not place sensitive data in map keys unless you intend it to remain visible.
//!
//! ## Set Redaction Can Collapse Elements
//!
//! For set containers (`HashSet`, `BTreeSet`), redaction is applied to each
//! element and the results are collected back into a set. If redaction changes
//! equality or ordering (e.g., multiple values redact to `"[REDACTED]"`), the
//! resulting set may shrink.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    hash::Hash,
    marker::PhantomData,
};

use super::{redact::RedactableMapper, traits::RedactableContainer};

// =============================================================================
// Passthrough implementations (scalars and primitives)
// =============================================================================

macro_rules! impl_redactable_container_passthrough {
    ($ty:ty) => {
        impl RedactableContainer for $ty {
            fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
                self
            }
        }
    };
}

impl_redactable_container_passthrough!(String);
impl_redactable_container_passthrough!(bool);
impl_redactable_container_passthrough!(char);
impl_redactable_container_passthrough!(i8);
impl_redactable_container_passthrough!(i16);
impl_redactable_container_passthrough!(i32);
impl_redactable_container_passthrough!(i64);
impl_redactable_container_passthrough!(i128);
impl_redactable_container_passthrough!(isize);
impl_redactable_container_passthrough!(u8);
impl_redactable_container_passthrough!(u16);
impl_redactable_container_passthrough!(u32);
impl_redactable_container_passthrough!(u64);
impl_redactable_container_passthrough!(u128);
impl_redactable_container_passthrough!(usize);
impl_redactable_container_passthrough!(f32);
impl_redactable_container_passthrough!(f64);
impl_redactable_container_passthrough!(());

impl<T> RedactableContainer for PhantomData<T> {
    fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
        self
    }
}

impl RedactableContainer for Cow<'_, str> {
    fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
        self
    }
}

// =============================================================================
// Wrapper container implementations
// =============================================================================

impl<T> RedactableContainer for Option<T>
where
    T: RedactableContainer,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        self.map(|value| value.redact_with(mapper))
    }
}

impl<T, E> RedactableContainer for Result<T, E>
where
    T: RedactableContainer,
    E: RedactableContainer,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        match self {
            Ok(value) => Ok(value.redact_with(mapper)),
            Err(err) => Err(err.redact_with(mapper)),
        }
    }
}

impl<T> RedactableContainer for Vec<T>
where
    T: RedactableContainer,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        self.into_iter()
            .map(|value| value.redact_with(mapper))
            .collect()
    }
}

impl<T> RedactableContainer for Box<T>
where
    T: RedactableContainer,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        Box::new((*self).redact_with(mapper))
    }
}

impl<T> RedactableContainer for std::sync::Arc<T>
where
    T: RedactableContainer + Clone,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        std::sync::Arc::new((*self).clone().redact_with(mapper))
    }
}

impl<T> RedactableContainer for std::rc::Rc<T>
where
    T: RedactableContainer + Clone,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        std::rc::Rc::new((*self).clone().redact_with(mapper))
    }
}

// =============================================================================
// Map implementations (values only, keys unchanged)
// =============================================================================

impl<K, V, S> RedactableContainer for HashMap<K, V, S>
where
    K: Hash + Eq,
    V: RedactableContainer,
    S: std::hash::BuildHasher + Clone,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        // NOTE: Map keys are not redacted by design. Only values are redacted to
        // preserve hashing/ordering invariants and avoid key collisions.
        let hasher = self.hasher().clone();
        let mut result = HashMap::with_hasher(hasher);
        result.extend(self.into_iter().map(|(k, v)| (k, v.redact_with(mapper))));
        result
    }
}

impl<K, V> RedactableContainer for BTreeMap<K, V>
where
    K: Ord,
    V: RedactableContainer,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        // NOTE: Map keys are not redacted by design. Only values are redacted to
        // preserve ordering invariants and avoid key collisions.
        self.into_iter()
            .map(|(k, v)| (k, v.redact_with(mapper)))
            .collect()
    }
}

// =============================================================================
// Set implementations
// =============================================================================

impl<T, S> RedactableContainer for HashSet<T, S>
where
    T: RedactableContainer + Hash + Eq,
    S: std::hash::BuildHasher + Clone,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        // NOTE: Redaction can collapse distinct values into equal ones, which may
        // reduce set cardinality (e.g., multiple values redacting to "[REDACTED]").
        let hasher = self.hasher().clone();
        let mut result = HashSet::with_hasher(hasher);
        result.extend(self.into_iter().map(|value| value.redact_with(mapper)));
        result
    }
}

impl<T> RedactableContainer for BTreeSet<T>
where
    T: RedactableContainer + Ord,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        // NOTE: Redaction can collapse distinct values into equal ones, which may
        // reduce set cardinality (e.g., multiple values redacting to "[REDACTED]").
        self.into_iter()
            .map(|value| value.redact_with(mapper))
            .collect()
    }
}

// =============================================================================
// Cell implementations
// =============================================================================

impl<T> RedactableContainer for std::cell::RefCell<T>
where
    T: RedactableContainer,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        std::cell::RefCell::new(self.into_inner().redact_with(mapper))
    }
}

impl<T> RedactableContainer for std::cell::Cell<T>
where
    T: RedactableContainer + Copy,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        std::cell::Cell::new(self.get().redact_with(mapper))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::{BTreeMap, BTreeSet, HashMap, HashSet},
        rc::Rc,
        sync::Arc,
    };

    use super::super::traits::Redactable;
    use crate::{Default, Sensitive};

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "json", derive(serde::Serialize))]
    struct SensitiveString {
        #[sensitive(Default)]
        value: String,
    }

    #[test]
    fn passthrough_string_unchanged() {
        let s = "hello".to_string();
        let redacted = s.clone().redact();
        assert_eq!(redacted, s);
    }

    #[test]
    fn passthrough_integers_unchanged() {
        assert_eq!(0i32.redact(), 0i32);
        assert_eq!(42u64.redact(), 42u64);
        assert_eq!((-1i8).redact(), -1i8);
    }

    #[test]
    fn option_traversal_redacts_inner() {
        let value = Some(SensitiveString {
            value: "secret".to_string(),
        });
        let redacted = value.redact();
        assert_eq!(redacted.unwrap().value, "[REDACTED]");
    }

    #[test]
    fn option_none_unchanged() {
        let o: Option<String> = None;
        let redacted = o.redact();
        assert!(redacted.is_none());
    }

    #[test]
    fn result_traversal_redacts_ok_and_err() {
        let ok_value: Result<SensitiveString, SensitiveString> = Ok(SensitiveString {
            value: "ok_secret".to_string(),
        });
        let redacted_ok = ok_value.redact().unwrap();
        assert_eq!(redacted_ok.value, "[REDACTED]");

        let err_value: Result<SensitiveString, SensitiveString> = Err(SensitiveString {
            value: "err_secret".to_string(),
        });
        let redacted_err = err_value.redact().unwrap_err();
        assert_eq!(redacted_err.value, "[REDACTED]");
    }

    #[test]
    fn vec_traversal_redacts_all_elements() {
        let values = vec![
            SensitiveString {
                value: "first".to_string(),
            },
            SensitiveString {
                value: "second".to_string(),
            },
        ];
        let redacted = values.redact();
        assert!(
            redacted
                .into_iter()
                .all(|value| value.value == "[REDACTED]")
        );
    }

    #[test]
    fn box_traversal_redacts_inner() {
        let b = Box::new(SensitiveString {
            value: "secret".to_string(),
        });
        let redacted = b.redact();
        assert_eq!(redacted.value, "[REDACTED]");
    }

    #[test]
    fn arc_traversal_redacts_inner() {
        let a = Arc::new(SensitiveString {
            value: "secret".to_string(),
        });
        let redacted = a.redact();
        assert_eq!(redacted.value, "[REDACTED]");
    }

    #[test]
    fn rc_traversal_redacts_inner() {
        let r = Rc::new(SensitiveString {
            value: "secret".to_string(),
        });
        let redacted = r.redact();
        assert_eq!(redacted.value, "[REDACTED]");
    }

    #[test]
    fn map_traversal_redacts_values() {
        let mut map: HashMap<String, SensitiveString> = HashMap::new();
        map.insert(
            "key".to_string(),
            SensitiveString {
                value: "secret".to_string(),
            },
        );
        let redacted = map.redact();
        assert_eq!(redacted["key"].value, "[REDACTED]");
    }

    #[test]
    fn btreemap_traversal_redacts_values() {
        let mut map: BTreeMap<String, SensitiveString> = BTreeMap::new();
        map.insert(
            "key".to_string(),
            SensitiveString {
                value: "secret".to_string(),
            },
        );
        let redacted = map.redact();
        assert_eq!(redacted["key"].value, "[REDACTED]");
    }

    #[test]
    fn map_keys_are_not_redacted_by_default() {
        let mut map: HashMap<String, SensitiveString> = HashMap::new();
        map.insert(
            "public_key".to_string(),
            SensitiveString {
                value: "secret".to_string(),
            },
        );
        let redacted = map.redact();
        assert!(redacted.contains_key("public_key"));
        assert_eq!(redacted["public_key"].value, "[REDACTED]");
    }

    #[test]
    fn map_keys_are_never_redacted() {
        #[derive(Clone, Hash, Eq, PartialEq, Sensitive)]
        #[cfg_attr(feature = "json", derive(serde::Serialize))]
        struct SensitiveKey {
            #[sensitive(Default)]
            value: String,
        }

        let mut map: HashMap<SensitiveKey, SensitiveString> = HashMap::new();
        let key = SensitiveKey {
            value: "key_secret".to_string(),
        };
        map.insert(
            key.clone(),
            SensitiveString {
                value: "secret".to_string(),
            },
        );

        let redacted = map.redact();
        assert!(redacted.contains_key(&key));
        assert_eq!(redacted[&key].value, "[REDACTED]");
    }

    #[test]
    fn btreeset_traversal_keeps_elements() {
        let mut set: BTreeSet<String> = BTreeSet::new();
        set.insert("public".to_string());
        let redacted = set.redact();
        assert!(redacted.contains("public"));
    }

    #[test]
    fn hashset_traversal_keeps_elements() {
        let mut set: HashSet<String> = HashSet::new();
        set.insert("public".to_string());
        let redacted = set.redact();
        assert!(redacted.contains("public"));
    }

    #[test]
    fn nested_container_traversal_redacts_inner() {
        let values = vec![Some(SensitiveString {
            value: "secret".to_string(),
        })];
        let redacted = values.redact();
        assert_eq!(redacted[0].as_ref().unwrap().value, "[REDACTED]");
    }

    #[test]
    fn refcell_traversal_redacts_inner() {
        let r = RefCell::new(SensitiveString {
            value: "secret".to_string(),
        });
        let redacted = r.redact();
        assert_eq!(redacted.borrow().value, "[REDACTED]");
    }

    #[test]
    fn cell_passthrough_unchanged() {
        let c = Cell::new(42u32);
        let redacted = c.redact();
        assert_eq!(redacted.get(), 42);
    }
}
