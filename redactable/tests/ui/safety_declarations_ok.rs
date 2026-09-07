use redactable::__private::DeclaredFormatting;
use redactable::{
    NotSensitiveDisplay, Redactable, RedactableWithFormatter, Sensitive, SensitiveDual,
};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    marker::PhantomData,
    rc::Rc,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, NotSensitiveDisplay)]
struct Public(u8);
impl Display for Public {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(&self.0, f)
    }
}
fn declared<T: DeclaredFormatting + ?Sized>() {}
fn structural<T: Redactable>() {}
fn formatting_map_bounds<K: Debug, V: DeclaredFormatting, S>() {
    declared::<HashMap<K, V, S>>();
    declared::<BTreeMap<K, V>>();
}
fn formatting_set_bounds<T: DeclaredFormatting, S>() {
    declared::<HashSet<T, S>>();
}

#[derive(Clone, serde::Serialize, SensitiveDual)]
#[error("{children}")]
struct Node<T> {
    children: Vec<Node<T>>,
    leaf: T,
}
#[derive(Clone, serde::Serialize, SensitiveDual)]
#[error("{next}")]
struct A {
    next: Option<Box<B>>,
}
#[derive(Clone, serde::Serialize, SensitiveDual)]
#[error("{next}")]
struct B {
    next: Option<Box<A>>,
}
type Alias = Option<Box<AliasNode>>;
#[derive(Clone, serde::Serialize, SensitiveDual)]
#[error("{next}")]
struct AliasNode {
    #[redactable(recursive)]
    next: Alias,
}
#[derive(Clone, serde::Serialize, SensitiveDual)]
#[error("{marker}")]
struct Marker<T> {
    marker: PhantomData<T>,
}

pub mod api {
    use redactable::SensitiveDisplay;
    #[derive(SensitiveDisplay)]
    #[error("selected")]
    struct Private;
    #[derive(SensitiveDisplay)]
    #[error("{field}")]
    pub struct PublicType {
        field: Private,
    }
}
// A foreign type that is not `Redactable` still needs the `#[not_sensitive]`
// declaration; since 0.12 it must also satisfy the container's `Clone +
// Serialize` bounds, so an unclonable foreign type (`std::io::Error`) has to be
// projected before it can live in a `Sensitive` container.
#[derive(Clone, serde::Serialize, Sensitive)]
struct ForeignPublic {
    #[not_sensitive]
    elapsed: Duration,
}

fn main() {
    macro_rules! containers {
        ($($ty:ty),+ $(,)?) => { $(declared::<$ty>(); structural::<$ty>();)+ };
    }
    containers!(Option<Public>, Result<Public,Public>, Vec<Public>, VecDeque<Public>,
        [Public;2], Box<Public>, Rc<Public>, Arc<Public>, Cell<Public>, RefCell<Public>,
        Mutex<Public>, RwLock<Public>, HashMap<String,Public>, BTreeMap<String,Public>,
        HashSet<Public>, BTreeSet<Public>, (Public,), (Public,Public),
        (Public,Public,Public), (Public,Public,Public,Public));
    declared::<[Public]>();
    declared::<&Public>();
    let value = Node {
        children: vec![],
        leaf: Public(7),
    }
    .redact();
    assert_eq!(value.leaf.0, 7);
    assert_eq!(
        A {
            next: Some(Box::new(B { next: None }))
        }
        .redacted_display()
        .to_string(),
        "Some(None)"
    );
    assert_eq!(
        AliasNode { next: None }.redacted_display().to_string(),
        "None"
    );
    let _ = Marker::<String> {
        marker: PhantomData,
    }
    .redact();
    let _ = ForeignPublic {
        elapsed: Duration::from_secs(1),
    }
    .redact();
    #[cfg(feature = "json")]
    {
        use serde_json::Value;
        declared::<Value>();
    }
}
