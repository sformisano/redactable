//! Redacted display formatting support.
//!
//! This module provides types for redacted string formatting:
//!
//! - [`RedactableDisplay`]: Trait for types that can format redacted display strings
//! - [`RedactedDisplayRef`]: Display wrapper that uses `fmt_redacted`

use super::output::{RedactedOutput, ToRedactedOutput};

// =============================================================================
// RedactableDisplay - Trait for redacted display formatting
// =============================================================================

/// Formats a redacted string representation without requiring `Clone` or `Serialize`.
///
/// This is intended for types that want redacted logging output while keeping
/// their own `Display` implementations.
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
