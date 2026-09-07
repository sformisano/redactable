//! Field admission for generated sensitive traversal and formatting.

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    fmt::Debug,
    marker::PhantomData,
    rc::Rc,
    sync::{Arc, Mutex, RwLock},
};

use crate::{Redactable, RedactableWithFormatter, SensitiveValue};
use serde_json::Value;

/// An explicit declaration about a type's redacted formatting.
///
/// Sensitive display derives implement this companion automatically. A reviewed
/// manual formatter can opt in with an empty implementation. This declaration
/// does not verify the formatter's policy or the contents it selects.
#[diagnostic::on_unimplemented(
    message = "`{Self}` has no declared redacted formatting",
    label = "this formatted field needs a redaction declaration",
    note = "select `#[sensitive(Policy)]`, use a declared type, or explicitly mark the field `#[not_sensitive]`",
    note = "for a local container, derive `SensitiveDisplay` or `SensitiveDual` and declare its formatted fields; reviewed manual formatters may implement `redactable::__private::DeclaredFormatting`"
)]
pub trait DeclaredFormatting: RedactableWithFormatter {}

/// An explicit declaration that a whole type carries no sensitive data.
///
/// The `NotSensitive` derive implements this companion automatically. It
/// records the author's declaration so the generated raw-JSON producer accepts
/// only declared types; it does not inspect what the type contains.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not declared free of sensitive data",
    label = "this value has no public declaration",
    note = "derive `NotSensitive` on the type to declare it public",
    note = "or log a value you do not own through `BypassJsonRedaction`"
)]
pub trait DeclaredNotSensitive {}

/// Checks a field even when recursive implementation bounds are omitted.
pub fn require_declared_formatting<T: DeclaredFormatting + ?Sized>(_: &T) {}

/// Checks admission without replacing the caller's structural mapper.
pub fn require_declared_redaction<T: Redactable>(_: &T) {}

impl<T: DeclaredFormatting + ?Sized> DeclaredFormatting for &T {}
impl<T> DeclaredFormatting for PhantomData<T> {}
impl<T, P> DeclaredFormatting for SensitiveValue<T, P> where
    SensitiveValue<T, P>: RedactableWithFormatter
{
}

impl<T: DeclaredFormatting> DeclaredFormatting for Option<T> {}
impl<T: DeclaredFormatting, E: DeclaredFormatting> DeclaredFormatting for Result<T, E> {}
impl<T: DeclaredFormatting> DeclaredFormatting for Vec<T> {}
impl<T: DeclaredFormatting> DeclaredFormatting for VecDeque<T> {}
impl<T: DeclaredFormatting> DeclaredFormatting for [T] {}
impl<T: DeclaredFormatting, const N: usize> DeclaredFormatting for [T; N] {}
impl<T: DeclaredFormatting + ?Sized> DeclaredFormatting for Box<T> {}
impl<T: DeclaredFormatting + ?Sized> DeclaredFormatting for Rc<T> {}
impl<T: DeclaredFormatting + ?Sized> DeclaredFormatting for Arc<T> {}
impl<T: DeclaredFormatting + Copy> DeclaredFormatting for Cell<T> {}
impl<T: DeclaredFormatting + ?Sized> DeclaredFormatting for RefCell<T> {}
impl<T: DeclaredFormatting + ?Sized> DeclaredFormatting for Mutex<T> {}
impl<T: DeclaredFormatting + ?Sized> DeclaredFormatting for RwLock<T> {}
impl<K: Debug, V: DeclaredFormatting, S> DeclaredFormatting for HashMap<K, V, S> {}
impl<K: Debug, V: DeclaredFormatting> DeclaredFormatting for BTreeMap<K, V> {}
impl<T: DeclaredFormatting, S> DeclaredFormatting for HashSet<T, S> {}
impl<T: DeclaredFormatting> DeclaredFormatting for BTreeSet<T> {}

macro_rules! declared_tuple {
    ($($element:ident),+) => {
        impl<$($element: DeclaredFormatting),+> DeclaredFormatting for ($($element,)+) {}
    };
}

declared_tuple!(T0);
declared_tuple!(T0, T1);
declared_tuple!(T0, T1, T2);
declared_tuple!(T0, T1, T2, T3);

impl DeclaredFormatting for Value {}
