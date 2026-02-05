//! Redacted display formatting support.
//!
//! This module provides types for redacted string formatting:
//!
//! - [`RedactableDisplay`]: Trait for types that can format redacted display strings
//! - [`RedactedDisplayRef`]: Display wrapper that uses `fmt_redacted`
//!
//! # Passthrough Implementations
//!
//! Common scalar types implement `RedactableDisplay` as passthrough (unchanged output):
//! `String`, `str`, `bool`, `char`, integers, floats, `Cow<str>`, `PhantomData`, `()`.
//!
//! Feature-gated types: `chrono` date/time types, `time` crate types, `Uuid`.

use std::{
    borrow::Cow,
    cmp::Ordering,
    marker::PhantomData,
    num::{
        NonZeroI8, NonZeroI16, NonZeroI32, NonZeroI64, NonZeroI128, NonZeroIsize, NonZeroU8,
        NonZeroU16, NonZeroU32, NonZeroU64, NonZeroU128, NonZeroUsize,
    },
    time::{Duration, Instant, SystemTime},
};

// =============================================================================
// RedactableDisplay - Trait for redacted display formatting
// =============================================================================

/// Formats a redacted string representation without requiring `Clone` or `Serialize`.
///
/// This is intended for types that want redacted logging output while keeping
/// their own `Display` implementations.
///
/// Common scalars (`String`, `bool`, integers, etc.) implement this as passthrough,
/// while types deriving `SensitiveDisplay` implement it with redaction logic.
pub trait RedactableDisplay {
    /// Formats a redacted representation of `self`.
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;

    /// Returns a wrapper that implements `Display` using `fmt_redacted`.
    fn redacted_display(&self) -> RedactedDisplayRef<'_, Self>
    where
        Self: Sized,
    {
        RedactedDisplayRef(self)
    }
}

// =============================================================================
// RedactedDisplayRef - Display wrapper for redacted display strings
// =============================================================================

/// Display wrapper that uses `RedactableDisplay::fmt_redacted`.
pub struct RedactedDisplayRef<'a, T: ?Sized>(&'a T);

impl<T: RedactableDisplay + ?Sized> std::fmt::Display for RedactedDisplayRef<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt_redacted(f)
    }
}

impl<T: RedactableDisplay + ?Sized> std::fmt::Debug for RedactedDisplayRef<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt_redacted(f)
    }
}

// =============================================================================
// Passthrough RedactableDisplay implementations
// =============================================================================

macro_rules! impl_redactable_display_passthrough {
    ($ty:ty) => {
        impl crate::redaction::display::RedactableDisplay for $ty {
            fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(self, f)
            }
        }
    };
}

macro_rules! impl_redactable_display_passthrough_debug {
    ($ty:ty) => {
        impl crate::redaction::display::RedactableDisplay for $ty {
            fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Debug::fmt(self, f)
            }
        }
    };
}

impl<T: ?Sized + RedactableDisplay> RedactableDisplay for &T {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        (*self).fmt_redacted(f)
    }
}

impl_redactable_display_passthrough!(String);
impl_redactable_display_passthrough!(str);
impl_redactable_display_passthrough!(bool);
impl_redactable_display_passthrough!(char);
impl_redactable_display_passthrough!(i8);
impl_redactable_display_passthrough!(i16);
impl_redactable_display_passthrough!(i32);
impl_redactable_display_passthrough!(i64);
impl_redactable_display_passthrough!(i128);
impl_redactable_display_passthrough!(isize);
impl_redactable_display_passthrough!(u8);
impl_redactable_display_passthrough!(u16);
impl_redactable_display_passthrough!(u32);
impl_redactable_display_passthrough!(u64);
impl_redactable_display_passthrough!(u128);
impl_redactable_display_passthrough!(usize);
impl_redactable_display_passthrough!(f32);
impl_redactable_display_passthrough!(f64);
impl_redactable_display_passthrough!(Cow<'_, str>);

// NonZero integer passthrough implementations
impl_redactable_display_passthrough!(NonZeroI8);
impl_redactable_display_passthrough!(NonZeroI16);
impl_redactable_display_passthrough!(NonZeroI32);
impl_redactable_display_passthrough!(NonZeroI64);
impl_redactable_display_passthrough!(NonZeroI128);
impl_redactable_display_passthrough!(NonZeroIsize);
impl_redactable_display_passthrough!(NonZeroU8);
impl_redactable_display_passthrough!(NonZeroU16);
impl_redactable_display_passthrough!(NonZeroU32);
impl_redactable_display_passthrough!(NonZeroU64);
impl_redactable_display_passthrough!(NonZeroU128);
impl_redactable_display_passthrough!(NonZeroUsize);

// std::time and ordering passthrough implementations
impl_redactable_display_passthrough_debug!(Duration);
impl_redactable_display_passthrough_debug!(Instant);
impl_redactable_display_passthrough_debug!(SystemTime);
impl_redactable_display_passthrough_debug!(Ordering);

impl RedactableDisplay for () {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("()")
    }
}

impl<T> RedactableDisplay for PhantomData<T> {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[cfg(feature = "chrono")]
mod chrono_passthrough {
    use chrono::{
        DateTime, Duration, FixedOffset, Local, Month, NaiveDate, NaiveDateTime, NaiveTime, Utc,
        Weekday,
    };

    impl_redactable_display_passthrough!(DateTime<Utc>);
    impl_redactable_display_passthrough!(DateTime<Local>);
    impl_redactable_display_passthrough!(DateTime<FixedOffset>);
    impl_redactable_display_passthrough!(Utc);
    impl_redactable_display_passthrough!(NaiveDateTime);
    impl_redactable_display_passthrough!(NaiveDate);
    impl_redactable_display_passthrough!(NaiveTime);
    impl_redactable_display_passthrough_debug!(Duration);
    impl_redactable_display_passthrough_debug!(Month);
    impl_redactable_display_passthrough_debug!(Weekday);
}

#[cfg(feature = "time")]
mod time_passthrough {
    use time::{
        Date, Duration, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset, Weekday,
    };

    impl_redactable_display_passthrough!(OffsetDateTime);
    impl_redactable_display_passthrough!(PrimitiveDateTime);
    impl_redactable_display_passthrough!(Date);
    impl_redactable_display_passthrough!(Time);
    impl_redactable_display_passthrough_debug!(Duration);
    impl_redactable_display_passthrough_debug!(UtcOffset);
    impl_redactable_display_passthrough_debug!(Month);
    impl_redactable_display_passthrough_debug!(Weekday);
}

#[cfg(feature = "uuid")]
mod uuid_passthrough {
    use uuid::Uuid;

    impl_redactable_display_passthrough!(Uuid);
}

// =============================================================================
// Container RedactableDisplay implementations
// =============================================================================

impl<T: RedactableDisplay> RedactableDisplay for Option<T> {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Some(value) => f
                .debug_tuple("Some")
                .field(&value.redacted_display())
                .finish(),
            None => f.write_str("None"),
        }
    }
}

impl<T: RedactableDisplay> RedactableDisplay for Vec<T> {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list = f.debug_list();
        for item in self {
            list.entry(&item.redacted_display());
        }
        list.finish()
    }
}

impl<T: RedactableDisplay> RedactableDisplay for [T] {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list = f.debug_list();
        for item in self {
            list.entry(&item.redacted_display());
        }
        list.finish()
    }
}

impl<T: RedactableDisplay> RedactableDisplay for std::collections::VecDeque<T> {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list = f.debug_list();
        for item in self {
            list.entry(&item.redacted_display());
        }
        list.finish()
    }
}

impl<T: RedactableDisplay + ?Sized> RedactableDisplay for Box<T> {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        (**self).fmt_redacted(f)
    }
}

impl<T: RedactableDisplay + ?Sized> RedactableDisplay for std::sync::Arc<T> {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        (**self).fmt_redacted(f)
    }
}

impl<T: RedactableDisplay + ?Sized> RedactableDisplay for std::rc::Rc<T> {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        (**self).fmt_redacted(f)
    }
}

impl<T: RedactableDisplay, E: RedactableDisplay> RedactableDisplay for Result<T, E> {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ok(value) => f
                .debug_tuple("Ok")
                .field(&value.redacted_display())
                .finish(),
            Err(err) => f.debug_tuple("Err").field(&err.redacted_display()).finish(),
        }
    }
}

impl<K, V, S> RedactableDisplay for std::collections::HashMap<K, V, S>
where
    K: std::fmt::Debug,
    V: RedactableDisplay,
{
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut map = f.debug_map();
        for (key, value) in self {
            map.entry(key, &value.redacted_display());
        }
        map.finish()
    }
}

impl<K, V> RedactableDisplay for std::collections::BTreeMap<K, V>
where
    K: std::fmt::Debug,
    V: RedactableDisplay,
{
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut map = f.debug_map();
        for (key, value) in self {
            map.entry(key, &value.redacted_display());
        }
        map.finish()
    }
}

impl<T, S> RedactableDisplay for std::collections::HashSet<T, S>
where
    T: RedactableDisplay,
{
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut set = f.debug_set();
        for item in self {
            set.entry(&item.redacted_display());
        }
        set.finish()
    }
}

impl<T> RedactableDisplay for std::collections::BTreeSet<T>
where
    T: RedactableDisplay,
{
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut set = f.debug_set();
        for item in self {
            set.entry(&item.redacted_display());
        }
        set.finish()
    }
}

impl<T: RedactableDisplay + Copy> RedactableDisplay for std::cell::Cell<T> {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.get().fmt_redacted(f)
    }
}

impl<T: RedactableDisplay + ?Sized> RedactableDisplay for std::cell::RefCell<T> {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.borrow().fmt_redacted(f)
    }
}

// =============================================================================
// serde_json::Value support (feature-gated)
// =============================================================================
//
// serde_json::Value always displays as "[REDACTED]" since it's an opaque type
// that could contain arbitrary sensitive data.

#[cfg(feature = "json")]
impl RedactableDisplay for serde_json::Value {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
        rc::Rc,
        sync::Arc,
    };

    use super::RedactableDisplay;
    use crate::SensitiveDisplay;

    #[derive(Eq, Hash, Ord, PartialEq, PartialOrd)]
    struct Key(&'static str);

    impl std::fmt::Debug for Key {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl RedactableDisplay for Key {
        fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("[REDACTED]")
        }
    }

    #[test]
    fn option_some_displays_some() {
        let opt = Some("hello".to_string());
        assert_eq!(format!("{}", opt.redacted_display()), "Some(hello)");
    }

    #[test]
    fn option_none_displays_none() {
        let opt: Option<String> = None;
        assert_eq!(format!("{}", opt.redacted_display()), "None");
    }

    #[test]
    fn vec_displays_elements() {
        let v = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert_eq!(format!("{}", v.redacted_display()), "[a, b, c]");
    }

    #[test]
    fn vec_empty_displays_brackets() {
        let v: Vec<String> = vec![];
        assert_eq!(format!("{}", v.redacted_display()), "[]");
    }

    #[test]
    fn slice_displays_elements() {
        let v = vec!["a".to_string(), "b".to_string()];
        let slice: &[String] = &v;
        assert_eq!(format!("{}", super::RedactedDisplayRef(slice)), "[a, b]");
    }

    #[test]
    fn vecdeque_displays_elements() {
        let mut v = VecDeque::new();
        v.push_back("a".to_string());
        v.push_back("b".to_string());
        assert_eq!(format!("{}", v.redacted_display()), "[a, b]");
    }

    #[test]
    fn box_displays_inner() {
        let b = Box::new("boxed".to_string());
        assert_eq!(format!("{}", b.redacted_display()), "boxed");
    }

    #[test]
    fn arc_displays_inner() {
        let a = Arc::new("arced".to_string());
        assert_eq!(format!("{}", a.redacted_display()), "arced");
    }

    #[test]
    fn rc_displays_inner() {
        let r = Rc::new("rced".to_string());
        assert_eq!(format!("{}", r.redacted_display()), "rced");
    }

    #[test]
    fn result_ok_displays_ok() {
        let r: Result<String, String> = Ok("success".to_string());
        assert_eq!(format!("{}", r.redacted_display()), "Ok(success)");
    }

    #[test]
    fn result_err_displays_err() {
        let r: Result<String, String> = Err("failure".to_string());
        assert_eq!(format!("{}", r.redacted_display()), "Err(failure)");
    }

    #[test]
    fn btreemap_displays_entries_with_debug_keys() {
        let mut m = BTreeMap::new();
        m.insert(Key("key"), "value".to_string());
        assert_eq!(format!("{}", m.redacted_display()), "{key: value}");
    }

    #[test]
    fn btreemap_empty_displays_braces() {
        let m: BTreeMap<Key, String> = BTreeMap::new();
        assert_eq!(format!("{}", m.redacted_display()), "{}");
    }

    #[test]
    fn hashmap_displays_entries_with_debug_keys() {
        let mut m = HashMap::new();
        m.insert(Key("key"), "value".to_string());
        assert_eq!(format!("{}", m.redacted_display()), "{key: value}");
    }

    #[test]
    fn btreeset_displays_elements() {
        let mut s = BTreeSet::new();
        s.insert("a".to_string());
        s.insert("b".to_string());
        assert_eq!(format!("{}", s.redacted_display()), "{a, b}");
    }

    #[test]
    fn btreeset_empty_displays_braces() {
        let s: BTreeSet<String> = BTreeSet::new();
        assert_eq!(format!("{}", s.redacted_display()), "{}");
    }

    #[test]
    fn hashset_displays_elements() {
        let mut s = HashSet::new();
        s.insert("a".to_string());
        assert_eq!(format!("{}", s.redacted_display()), "{a}");
    }

    #[test]
    fn cell_displays_inner() {
        let c = Cell::new(42u32);
        assert_eq!(format!("{}", c.redacted_display()), "42");
    }

    #[test]
    fn refcell_displays_inner() {
        let r = RefCell::new("refcelled".to_string());
        assert_eq!(format!("{}", r.redacted_display()), "refcelled");
    }

    #[test]
    fn nested_option_vec_displays() {
        let v: Vec<Option<String>> = vec![Some("a".to_string()), None, Some("c".to_string())];
        assert_eq!(
            format!("{}", v.redacted_display()),
            "[Some(a), None, Some(c)]"
        );
    }

    #[test]
    fn nested_result_in_option_displays() {
        let opt: Option<Result<String, String>> = Some(Ok("nested".to_string()));
        assert_eq!(format!("{}", opt.redacted_display()), "Some(Ok(nested))");
    }

    #[test]
    fn sensitive_display_containers_use_redacted_display() {
        #[derive(SensitiveDisplay)]
        #[error("err {message}")]
        struct MyErr {
            message: String,
        }

        #[derive(SensitiveDisplay)]
        #[error("opt={opt:?} vec={vec:?} res={res:?}")]
        struct Wrap {
            opt: Option<String>,
            vec: Vec<String>,
            res: Result<String, String>,
        }

        let err = MyErr {
            message: "boom".to_string(),
        };
        assert_eq!(format!("{}", err.redacted_display()), "err boom");

        let wrap = Wrap {
            opt: Some("opt".to_string()),
            vec: vec!["v1".to_string(), "v2".to_string()],
            res: Err("err".to_string()),
        };
        assert_eq!(
            format!("{}", wrap.redacted_display()),
            "opt=Some(opt) vec=[v1, v2] res=Err(err)"
        );
    }
}
