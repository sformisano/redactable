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
mod ip_policy;
#[cfg(feature = "json")]
mod json;
mod output;
pub mod redact;
mod traits;
mod wrappers;

// Re-export core traits
// Re-export display types
pub use display::{PolicyRedactedFormatterRef, RedactableWithFormatter, RedactedFormatterRef};
// Re-export escape hatches
pub use escape_hatches::{
    NotSensitive, NotSensitiveDebug, NotSensitiveDebugExt, NotSensitiveDisplay,
    NotSensitiveDisplayExt, NotSensitiveExt,
};
#[cfg(feature = "json")]
pub use escape_hatches::{NotSensitiveJson, NotSensitiveJsonExt};
#[cfg(feature = "json")]
pub use output::serialize_redacted_json;
#[cfg(feature = "json")]
pub use output::{IntoRedactedJsonExt, RedactedJson, RedactedJsonExt, RedactedJsonRef};
// Re-export output types
pub use output::{
    IntoRedactedOutputExt, RedactedOutput, RedactedOutputExt, RedactedOutputRef, ToRedactedOutput,
};
// Re-export redaction machinery
pub use redact::{
    PolicyApplicable, PolicyApplicableRef, PolicyFormattingMapper, PolicyMapper, RedactableMapper,
    ScalarRedaction, apply_policy, apply_policy_ref, redact,
};
pub use traits::{Redactable, RedactableWithMapper, SensitiveWithPolicy};
// Re-export wrapper types
#[doc(hidden)]
pub use ip_policy::{IpPolicyApplicable, IpPolicyApplicableRef};
pub use wrappers::{NotSensitiveValue, SensitiveValue};
