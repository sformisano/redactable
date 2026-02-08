//! Redaction traversal and entrypoints.
//!
//! This module provides the machinery for applying redaction:
//!
//! - **`traits`**: Core traits (`RedactableWithMapper`, `SensitiveWithPolicy`, `Redactable`)
//! - **`redact`**: Application layer - the redaction machinery (`PolicyApplicable`, `RedactableMapper`)
//! - **`wrappers`**: Wrapper types (`SensitiveValue`, `NotSensitiveValue`)
//! - **`output`**: Output types for logging boundaries (`RedactedOutput`, `ToRedactedOutput`)
//! - **`display`**: Redacted display support (`RedactableWithFormatter`, `RedactedFormatterRef`)
//! - **`escape_hatches`**: Escape hatches for non-sensitive values
//! - **`containers`**: `RedactableWithMapper` implementations for std types
//!
//! Policy marker types and text policies live in `crate::policy`.

mod containers;
mod display;
mod escape_hatches;
#[cfg(feature = "json")]
mod json;
mod output;
mod redact;
mod traits;
mod wrappers;

// Re-export core traits
// Re-export display types
pub use display::{RedactableWithFormatter, RedactedFormatterRef};
// Re-export escape hatches
pub use escape_hatches::{
    NotSensitive, NotSensitiveDebug, NotSensitiveDebugExt, NotSensitiveDisplay,
    NotSensitiveDisplayExt, NotSensitiveExt,
};
#[cfg(feature = "json")]
pub use escape_hatches::{NotSensitiveJson, NotSensitiveJsonExt};
#[cfg(feature = "json")]
pub use output::{RedactedJson, RedactedJsonExt, RedactedJsonRef};
// Re-export output types
pub use output::{RedactedOutput, RedactedOutputExt, RedactedOutputRef, ToRedactedOutput};
// Re-export redaction machinery
pub use redact::{
    PolicyApplicable, PolicyApplicableRef, RedactableMapper, ScalarRedaction, apply_policy,
    apply_policy_ref, redact,
};
pub use traits::{Redactable, RedactableWithMapper, SensitiveWithPolicy};
// Re-export wrapper types
pub use wrappers::{NotSensitiveValue, SensitiveValue};
