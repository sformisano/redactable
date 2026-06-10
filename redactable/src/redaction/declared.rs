//! The [`DeclaredRedactable`] certification marker.
//!
//! `Redactable` is blanket-implemented over `RedactableWithMapper`, which
//! standard leaves (`String`, scalars, `Vec<String>`, ...) implement as no-op
//! passthroughs so unannotated fields can participate in traversal. That makes
//! `Redactable` alone too weak a bound for logging-boundary extension methods:
//! `password.redacted_output()` would compile, perform zero redaction, and
//! certify the raw value as redacted output.
//!
//! `DeclaredRedactable` closes that gap. It marks types whose redaction
//! behavior was *explicitly declared* - via the `Sensitive`, `NotSensitive`,
//! or `NotSensitiveDisplay` derives, the wrapper types, or a deliberate manual
//! implementation - and is forwarded through the same std containers that
//! redaction traversal walks. Passthrough leaves never implement it.

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    rc::Rc,
    sync::Arc,
};

/// Marker for types whose redaction behavior was explicitly declared.
///
/// Implemented automatically by the `Sensitive`, `NotSensitive`, and
/// `NotSensitiveDisplay` derives, by `SensitiveValue` / `NotSensitiveValue`,
/// and forwarded through std containers of such types. The logging-boundary
/// extension traits (`RedactedOutputExt`, `RedactedJsonExt`,
/// `SlogRedactedExt`) require this marker so raw passthrough values like
/// `String` cannot be certified as redacted output.
///
/// Implement this manually only for types whose `RedactableWithMapper`
/// implementation genuinely declares their redaction behavior; implementing it
/// on a passthrough type re-opens the leak this marker exists to prevent.
#[diagnostic::on_unimplemented(
    message = "`{Self}` has no declared redaction behavior",
    label = "raw values cannot be certified as redacted output",
    note = "derive `Sensitive`, `NotSensitive`, or `NotSensitiveDisplay` on the type",
    note = "or wrap the value in `SensitiveValue<T, P>` / `NotSensitiveValue<T>`"
)]
pub trait DeclaredRedactable {}

// Containers forward the declaration exactly like redaction traversal walks
// them. Map keys are exempt, mirroring values-only map redaction.

impl<T: DeclaredRedactable> DeclaredRedactable for Option<T> {}

impl<T: DeclaredRedactable, E: DeclaredRedactable> DeclaredRedactable for Result<T, E> {}

impl<T: DeclaredRedactable> DeclaredRedactable for Vec<T> {}

impl<T: DeclaredRedactable> DeclaredRedactable for Box<T> {}

impl<T: DeclaredRedactable> DeclaredRedactable for Arc<T> {}

impl<T: DeclaredRedactable> DeclaredRedactable for Rc<T> {}

impl<T: DeclaredRedactable> DeclaredRedactable for RefCell<T> {}

impl<T: DeclaredRedactable> DeclaredRedactable for Cell<T> {}

impl<K, V: DeclaredRedactable, S> DeclaredRedactable for HashMap<K, V, S> {}

impl<K, V: DeclaredRedactable> DeclaredRedactable for BTreeMap<K, V> {}

impl<T: DeclaredRedactable, S> DeclaredRedactable for HashSet<T, S> {}

impl<T: DeclaredRedactable> DeclaredRedactable for BTreeSet<T> {}

// `serde_json::Value` redaction is declared by the crate itself: the json
// module fully redacts it as an opaque leaf, so certifying it is sound.
#[cfg(feature = "json")]
impl DeclaredRedactable for serde_json::Value {}
