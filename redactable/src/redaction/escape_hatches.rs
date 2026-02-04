//! Escape hatches for explicitly non-sensitive values.
//!
//! This module provides wrappers and extension traits for marking values as
//! explicitly non-sensitive at logging boundaries:
//!
//! - [`NotSensitiveDisplay`]: Wrapper using `Display` formatting
//! - [`NotSensitiveDebug`]: Wrapper using `Debug` formatting
//! - [`NotSensitiveJson`]: Wrapper using JSON serialization (requires `json` feature)
//!
//! And their corresponding extension traits:
//! - [`NotSensitiveExt`]: Provides `.not_sensitive()`
//! - [`NotSensitiveDebugExt`]: Provides `.not_sensitive_debug()`
//! - [`NotSensitiveJsonExt`]: Provides `.not_sensitive_json()`

#[cfg(feature = "json")]
use serde::Serialize;

use super::output::{RedactedOutput, ToRedactedOutput};

// =============================================================================
// NotSensitiveDisplay - Wrapper using Display
// =============================================================================

/// Wrapper for explicitly non-sensitive values using `Display`.
///
/// Use `.not_sensitive()` to declare a value safe to log.
pub struct NotSensitiveDisplay<'a, T: ?Sized>(&'a T);

impl<T: ?Sized> NotSensitiveDisplay<'_, T> {
    /// Returns the inner value.
    #[must_use]
    pub fn inner(&self) -> &T {
        self.0
    }
}

impl<T> ToRedactedOutput for NotSensitiveDisplay<'_, T>
where
    T: std::fmt::Display + ?Sized,
{
    fn to_redacted_output(&self) -> RedactedOutput {
        RedactedOutput::Text(self.0.to_string())
    }
}

impl<T> std::fmt::Debug for NotSensitiveDisplay<'_, T>
where
    T: std::fmt::Display + ?Sized,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("NotSensitiveDisplay")
            .field(&self.0.to_string())
            .finish()
    }
}

// =============================================================================
// NotSensitiveDebug - Wrapper using Debug
// =============================================================================

/// Wrapper for explicitly non-sensitive values using `Debug`.
///
/// Use `.not_sensitive_debug()` to declare a value safe to log via `Debug`
/// formatting.
pub struct NotSensitiveDebug<'a, T: ?Sized>(&'a T);

impl<T: ?Sized> NotSensitiveDebug<'_, T> {
    /// Returns the inner value.
    #[must_use]
    pub fn inner(&self) -> &T {
        self.0
    }
}

impl<T> ToRedactedOutput for NotSensitiveDebug<'_, T>
where
    T: std::fmt::Debug + ?Sized,
{
    fn to_redacted_output(&self) -> RedactedOutput {
        RedactedOutput::Text(format!("{:?}", self.0))
    }
}

impl<T> std::fmt::Debug for NotSensitiveDebug<'_, T>
where
    T: std::fmt::Debug + ?Sized,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("NotSensitiveDebug")
            .field(&self.to_redacted_output())
            .finish()
    }
}

// =============================================================================
// NotSensitiveJson - Wrapper using JSON serialization
// =============================================================================

/// Wrapper for explicitly non-sensitive values using JSON serialization.
///
/// Use `.not_sensitive_json()` to declare a value safe to log as JSON.
#[cfg(feature = "json")]
pub struct NotSensitiveJson<'a, T: ?Sized>(&'a T);

#[cfg(feature = "json")]
impl<T: ?Sized> NotSensitiveJson<'_, T> {
    /// Returns the inner value.
    #[must_use]
    pub fn inner(&self) -> &T {
        self.0
    }
}

#[cfg(feature = "json")]
impl<T> ToRedactedOutput for NotSensitiveJson<'_, T>
where
    T: Serialize + ?Sized,
{
    fn to_redacted_output(&self) -> RedactedOutput {
        match serde_json::to_value(self.0) {
            Ok(json) => RedactedOutput::Json(json),
            Err(err) => {
                RedactedOutput::Text(format!("Failed to serialize not-sensitive value: {err}"))
            }
        }
    }
}

#[cfg(feature = "json")]
impl<T> std::fmt::Debug for NotSensitiveJson<'_, T>
where
    T: Serialize + ?Sized,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("NotSensitiveJson")
            .field(&self.to_redacted_output())
            .finish()
    }
}

// =============================================================================
// Extension traits
// =============================================================================

/// Extension trait to mark values as explicitly non-sensitive for logging.
pub trait NotSensitiveExt {
    /// Wraps the value as explicitly non-sensitive for redacted logging.
    fn not_sensitive(&self) -> NotSensitiveDisplay<'_, Self>
    where
        Self: Sized;
}

impl<T> NotSensitiveExt for T
where
    T: std::fmt::Display,
{
    fn not_sensitive(&self) -> NotSensitiveDisplay<'_, Self> {
        NotSensitiveDisplay(self)
    }
}

/// Extension trait to mark values as explicitly non-sensitive using `Debug`.
pub trait NotSensitiveDebugExt {
    /// Wraps the value as explicitly non-sensitive using `Debug`.
    fn not_sensitive_debug(&self) -> NotSensitiveDebug<'_, Self>
    where
        Self: Sized;
}

impl<T> NotSensitiveDebugExt for T
where
    T: std::fmt::Debug,
{
    fn not_sensitive_debug(&self) -> NotSensitiveDebug<'_, Self> {
        NotSensitiveDebug(self)
    }
}

/// Extension trait to mark values as explicitly non-sensitive using JSON.
#[cfg(feature = "json")]
pub trait NotSensitiveJsonExt {
    /// Wraps the value as explicitly non-sensitive using JSON serialization.
    fn not_sensitive_json(&self) -> NotSensitiveJson<'_, Self>
    where
        Self: Sized;
}

#[cfg(feature = "json")]
impl<T> NotSensitiveJsonExt for T
where
    T: Serialize,
{
    fn not_sensitive_json(&self) -> NotSensitiveJson<'_, Self> {
        NotSensitiveJson(self)
    }
}
