use std::{
    cell::Cell,
    collections::{BTreeMap, HashMap, hash_map::DefaultHasher},
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::BuildHasherDefault,
    marker::PhantomData,
    rc::Rc,
    sync::Arc,
};

use redactable::{
    Email, NotSensitiveDisplay, BypassRedaction, Redactable, RedactableWithFormatter, Secret,
    Sensitive, SensitiveDisplay,
};

#[derive(Clone, serde::Serialize, Sensitive)]
struct Leaf {
    #[sensitive(Secret)]
    value: String,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
struct Key(u8);

type Hasher = BuildHasherDefault<DefaultHasher>;

#[derive(Clone, serde::Serialize, Sensitive)]
struct Complete<K, V, S> {
    #[serde(skip)]
    arc: Arc<V>,
    #[serde(skip)]
    rc: Rc<V>,
    #[not_sensitive]
    cell: Cell<u8>,
    hash: HashMap<K, V, S>,
    tree: BTreeMap<K, V>,
    foreign: BypassRedaction<PhantomData<fn() -> K>>,
}

#[derive(Clone, serde::Serialize, Sensitive)]
struct Tuple<K, V, S>(
    #[serde(skip)] Arc<V>,
    HashMap<K, V, S>,
    BypassRedaction<K>,
);

#[derive(Clone, serde::Serialize, Sensitive)]
enum Shapes<K, V, S> {
    Named { values: HashMap<K, V, S> },
    Tuple(#[serde(skip)] Rc<V>, BTreeMap<K, V>),
    Unit,
}

#[derive(serde::Serialize, SensitiveDisplay)]
#[error("email {email}")]
struct PolicyOutput<T> {
    #[sensitive(Email)]
    email: T,
}

#[derive(NotSensitiveDisplay)]
struct DebugDisplay<T>(T);

impl<T: Debug> Display for DebugDisplay<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{:?}", self.0)
    }
}

fn main() {
    let mut hash = HashMap::with_hasher(Hasher::default());
    hash.insert(
        Key(1),
        Leaf {
            value: "secret".into(),
        },
    );
    let mut tree = BTreeMap::new();
    tree.insert(
        Key(2),
        Leaf {
            value: "secret".into(),
        },
    );

    let value = Complete {
        arc: Arc::new(Leaf {
            value: "secret".into(),
        }),
        rc: Rc::new(Leaf {
            value: "secret".into(),
        }),
        cell: Cell::new(7),
        hash,
        tree,
        foreign: BypassRedaction(PhantomData),
    }
    .redact();
    assert_eq!(value.arc.value, "[REDACTED]");
    assert_eq!(value.hash[&Key(1)].value, "[REDACTED]");

    let _: Tuple<Key, Leaf, Hasher> = Tuple(
        Arc::new(Leaf {
            value: "secret".into(),
        }),
        HashMap::with_hasher(Hasher::default()),
        BypassRedaction(Key(3)),
    )
    .redact();
    let _: Shapes<Key, Leaf, Hasher> = Shapes::Unit.redact();
    let _ = PolicyOutput {
        email: String::from("alice@example.com"),
    }
    .redacted_display()
    .to_string();
    let _ = DebugDisplay(vec![1_u8, 2, 3]).to_string();
}
