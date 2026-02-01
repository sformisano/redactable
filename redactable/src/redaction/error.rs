//! Error redaction support.
//!
//! This module provides types for redacting error messages:
//!
//! - [`RedactableError`]: Trait for types that can format redacted error messages
//! - [`RedactedErrorRef`]: Display wrapper that uses `fmt_redacted`

use super::output::{RedactedOutput, ToRedactedOutput};

// =============================================================================
// RedactableError - Trait for redacted error formatting
// =============================================================================

/// Formats a redacted string representation without requiring `Clone` or `Serialize`.
///
/// This is intended for types (often errors) that want redacted logging output
/// while keeping their own `Display` implementations.
pub trait RedactableError {
    /// Formats a redacted representation of `self`.
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;

    /// Returns a wrapper that implements `Display` using `fmt_redacted`.
    fn redacted_error(&self) -> RedactedErrorRef<'_, Self>
    where
        Self: Sized,
    {
        RedactedErrorRef(self)
    }
}

// =============================================================================
// RedactedErrorRef - Display wrapper for redacted errors
// =============================================================================

/// Display wrapper that uses `RedactableError::fmt_redacted`.
pub struct RedactedErrorRef<'a, T: ?Sized>(&'a T);

impl<T: RedactableError + ?Sized> std::fmt::Display for RedactedErrorRef<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt_redacted(f)
    }
}

impl<T: RedactableError + ?Sized> std::fmt::Debug for RedactedErrorRef<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt_redacted(f)
    }
}

impl<T> ToRedactedOutput for T
where
    T: RedactableError,
{
    fn to_redacted_output(&self) -> RedactedOutput {
        RedactedOutput::Text(format!("{}", self.redacted_error()))
    }
}
