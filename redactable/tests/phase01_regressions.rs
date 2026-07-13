//! Runtime regressions for trait-directed traversal and complete-type bounds.

use std::{cell::Cell, collections::HashMap, hash::BuildHasherDefault, rc::Rc, sync::Arc};

use redactable::{Redactable, Secret, Sensitive};

const CANARY: &str = "phase01-runtime-canary-c81e";

#[derive(Clone, Sensitive)]
#[cfg_attr(feature = "slog", derive(serde::Serialize))]
struct SecretLeaf {
    #[sensitive(Secret)]
    value: String,
}

#[derive(Clone, Sensitive)]
#[cfg_attr(feature = "slog", derive(serde::Serialize))]
struct PhantomData<T> {
    value: T,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "slog", derive(serde::Serialize))]
struct Key(u8);

type Hasher = BuildHasherDefault<std::collections::hash_map::DefaultHasher>;

#[derive(Clone, Sensitive)]
#[cfg_attr(feature = "slog", derive(serde::Serialize))]
struct CompleteBounds {
    marker: PhantomData<SecretLeaf>,
    #[cfg_attr(feature = "slog", serde(skip))]
    arc: Arc<SecretLeaf>,
    #[cfg_attr(feature = "slog", serde(skip))]
    rc: Rc<SecretLeaf>,
    cell: Cell<u8>,
    map: HashMap<Key, SecretLeaf, Hasher>,
}

#[test]
fn traverses_user_phantom_data_and_complete_container_types() {
    let mut map = HashMap::with_hasher(Hasher::default());
    map.insert(
        Key(7),
        SecretLeaf {
            value: CANARY.into(),
        },
    );
    let value = CompleteBounds {
        marker: PhantomData {
            value: SecretLeaf {
                value: CANARY.into(),
            },
        },
        arc: Arc::new(SecretLeaf {
            value: CANARY.into(),
        }),
        rc: Rc::new(SecretLeaf {
            value: CANARY.into(),
        }),
        cell: Cell::new(9),
        map,
    }
    .redact();

    assert_eq!(value.marker.value.value, "[REDACTED]");
    assert_eq!(value.arc.value, "[REDACTED]");
    assert_eq!(value.rc.value, "[REDACTED]");
    assert_eq!(value.cell.get(), 9);
    assert_eq!(value.map[&Key(7)].value, "[REDACTED]");
    let debug = format!("{:?}", value.map[&Key(7)].value);
    assert!(!debug.contains(CANARY));
}
