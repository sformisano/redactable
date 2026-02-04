//! Output types for logging boundaries.
//!
//! This module provides types for producing logging-safe output:
//!
//! - [`RedactedOutput`]: The output enum (Text or Json)
//! - [`ToRedactedOutput`]: Trait for types that can produce redacted output
//! - [`RedactedOutputRef`]: Wrapper for explicit redacted output
//! - [`RedactedJsonRef`]: Wrapper for redacted JSON output

#[cfg(feature = "json")]
use serde::Serialize;
#[cfg(feature = "json")]
use serde_json::Value as JsonValue;

use super::{
    traits::{Redactable, RedactableWithPolicy},
    wrappers::SensitiveValue,
};
use crate::policy::RedactionPolicy;

// =============================================================================
// RedactedOutput - Output produced at logging boundaries
// =============================================================================

/// Output produced at a logging boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RedactedOutput {
    Text(String),
    #[cfg(feature = "json")]
    Json(JsonValue),
}

// =============================================================================
// ToRedactedOutput - Trait for producing logging-safe output
// =============================================================================

/// Produces a logging-safe output representation.
pub trait ToRedactedOutput {
    #[must_use]
    fn to_redacted_output(&self) -> RedactedOutput;
}

impl ToRedactedOutput for RedactedOutput {
    fn to_redacted_output(&self) -> RedactedOutput {
        self.clone()
    }
}

impl<T, P> ToRedactedOutput for SensitiveValue<T, P>
where
    T: RedactableWithPolicy<P>,
    P: RedactionPolicy,
{
    fn to_redacted_output(&self) -> RedactedOutput {
        RedactedOutput::Text(self.redacted())
    }
}

// =============================================================================
// RedactedOutputRef - Wrapper for explicit redacted output
// =============================================================================

/// Wrapper for explicitly redacting structured types.
///
/// Use `.redacted_output()` to opt into logging-safe output for types that
/// implement `Redactable + Clone + Debug`.
pub struct RedactedOutputRef<'a, T: ?Sized>(&'a T);

impl<T> ToRedactedOutput for RedactedOutputRef<'_, T>
where
    T: Redactable + Clone + std::fmt::Debug,
{
    fn to_redacted_output(&self) -> RedactedOutput {
        RedactedOutput::Text(format!("{:?}", self.0.clone().redact()))
    }
}

/// Extension trait to obtain a redacted output wrapper.
pub trait RedactedOutputExt {
    /// Wraps the value for explicit logging-safe output.
    fn redacted_output(&self) -> RedactedOutputRef<'_, Self>
    where
        Self: Sized;
}

impl<T> RedactedOutputExt for T
where
    T: Redactable + Clone + std::fmt::Debug,
{
    fn redacted_output(&self) -> RedactedOutputRef<'_, Self> {
        RedactedOutputRef(self)
    }
}

// =============================================================================
// RedactedJsonRef - Wrapper for redacted JSON output
// =============================================================================

/// Wrapper for redacted JSON output from structured types.
#[cfg(feature = "json")]
pub struct RedactedJsonRef<'a, T: ?Sized>(&'a T);

#[cfg(feature = "json")]
impl<T> ToRedactedOutput for RedactedJsonRef<'_, T>
where
    T: Redactable + Clone + Serialize,
{
    fn to_redacted_output(&self) -> RedactedOutput {
        let redacted = self.0.clone().redact();
        match serde_json::to_value(redacted) {
            Ok(json) => RedactedOutput::Json(json),
            Err(err) => RedactedOutput::Text(format!("Failed to serialize redacted value: {err}")),
        }
    }
}

/// Extension trait to obtain a redacted JSON output wrapper.
#[cfg(feature = "json")]
pub trait RedactedJsonExt {
    /// Wraps the value for explicit redacted JSON output.
    fn redacted_json(&self) -> RedactedJsonRef<'_, Self>
    where
        Self: Sized;
}

#[cfg(feature = "json")]
impl<T> RedactedJsonExt for T
where
    T: Redactable + Clone + Serialize,
{
    fn redacted_json(&self) -> RedactedJsonRef<'_, Self> {
        RedactedJsonRef(self)
    }
}
