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

use std::{borrow::Cow, marker::PhantomData};

use super::output::{RedactedOutput, ToRedactedOutput};

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

impl<T> ToRedactedOutput for T
where
    T: RedactableDisplay,
{
    fn to_redacted_output(&self) -> RedactedOutput {
        RedactedOutput::Text(format!("{}", self.redacted_display()))
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
    use chrono::{DateTime, FixedOffset, Local, NaiveDate, NaiveDateTime, NaiveTime, Utc};

    impl_redactable_display_passthrough!(DateTime<Utc>);
    impl_redactable_display_passthrough!(DateTime<Local>);
    impl_redactable_display_passthrough!(DateTime<FixedOffset>);
    impl_redactable_display_passthrough!(Utc);
    impl_redactable_display_passthrough!(NaiveDateTime);
    impl_redactable_display_passthrough!(NaiveDate);
    impl_redactable_display_passthrough!(NaiveTime);
}

#[cfg(feature = "time")]
mod time_passthrough {
    use time::{Date, OffsetDateTime, PrimitiveDateTime, Time};

    impl_redactable_display_passthrough!(OffsetDateTime);
    impl_redactable_display_passthrough!(PrimitiveDateTime);
    impl_redactable_display_passthrough!(Date);
    impl_redactable_display_passthrough!(Time);
}

#[cfg(feature = "uuid")]
mod uuid_passthrough {
    use uuid::Uuid;

    impl_redactable_display_passthrough!(Uuid);
}
