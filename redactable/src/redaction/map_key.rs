//! Admission of map keys retained by structural redaction.

use std::{
    borrow::Cow,
    cell::{Cell, RefCell},
    marker::PhantomData,
    num::{
        NonZeroI8, NonZeroI16, NonZeroI32, NonZeroI64, NonZeroI128, NonZeroIsize, NonZeroU8,
        NonZeroU16, NonZeroU32, NonZeroU64, NonZeroU128, NonZeroUsize,
    },
    rc::Rc,
    sync::Arc,
};

use super::wrappers::BypassRedaction;

/// Declares that a structurally redacted map may expose this key unchanged.
///
/// Keys can appear through their own `Debug` and Serde representations.
/// Derive [`NotSensitive`](crate::NotSensitive) to declare a whole type public,
/// implement this marker on a local type to declare it public as a key, or
/// wrap a reviewed key in [`BypassRedaction`]. The serializer determines
/// which key representations it can encode.
///
/// String keys, booleans, characters, integers (including nonzero integers)
/// and unit have built-in declarations. References and supported standard
/// wrappers forward the inner key's declaration.
///
/// The `mask-map-keys` feature changes the JSON projection after admission.
/// IP-address policies have additional restrictions on map keys.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not declared public as a map key",
    label = "structural redaction keeps map keys unchanged",
    note = "derive `NotSensitive` for a public key type, implement `PublicMapKey` on a reviewed local key, or use `BypassRedaction<K>`",
    note = "use `#[not_sensitive]` on the whole field only if its keys and values are public"
)]
pub trait PublicMapKey {}

macro_rules! public_keys {
    ($($ty:ty),+ $(,)?) => { $(impl PublicMapKey for $ty {})+ };
}

public_keys!(
    str,
    String,
    Cow<'_, str>,
    (),
    bool,
    char,
    i8,
    i16,
    i32,
    i64,
    i128,
    isize,
    u8,
    u16,
    u32,
    u64,
    u128,
    usize,
    NonZeroI8,
    NonZeroI16,
    NonZeroI32,
    NonZeroI64,
    NonZeroI128,
    NonZeroIsize,
    NonZeroU8,
    NonZeroU16,
    NonZeroU32,
    NonZeroU64,
    NonZeroU128,
    NonZeroUsize,
);

impl<T: PublicMapKey + ?Sized> PublicMapKey for &T {}
impl<T: PublicMapKey + ?Sized> PublicMapKey for &mut T {}
impl<T: PublicMapKey + ?Sized> PublicMapKey for Box<T> {}
impl<T: PublicMapKey + ?Sized> PublicMapKey for Rc<T> {}
impl<T: PublicMapKey + ?Sized> PublicMapKey for Arc<T> {}
impl<T: PublicMapKey + ?Sized> PublicMapKey for Cell<T> {}
impl<T: PublicMapKey + ?Sized> PublicMapKey for RefCell<T> {}
impl<T: ?Sized> PublicMapKey for PhantomData<T> {}
impl<T> PublicMapKey for BypassRedaction<T> {}
