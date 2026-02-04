//! Redaction traversal and entrypoints.
//!
//! This module provides the machinery for applying redaction:
//!
//! - **`traits`**: Core traits (`RedactableContainer`, `RedactableLeaf`, `Redactable`)
//! - **`redact`**: Application layer - the redaction machinery (`PolicyApplicable`, `RedactableMapper`)
//! - **`wrappers`**: Wrapper types (`SensitiveValue`, `NotSensitiveValue`)
//! - **`output`**: Output types for logging boundaries (`RedactedOutput`, `ToRedactedOutput`)
//! - **`display`**: Redacted display support (`RedactableDisplay`, `RedactedDisplayRef`)
//! - **`escape_hatches`**: Escape hatches for non-sensitive values
//! - **`containers`**: `RedactableContainer` implementations for std types
//!
//! Policy marker types and text policies live in `crate::policy`.

mod containers;
mod display;
mod escape_hatches;
mod output;
mod redact;
mod traits;
mod wrappers;

// Re-export core traits
// Re-export display types
pub use display::{RedactableDisplay, RedactedDisplayRef};
// Re-export escape hatches
pub use escape_hatches::{
    NotSensitiveDebug, NotSensitiveDebugExt, NotSensitiveDisplay, NotSensitiveExt,
};
#[cfg(feature = "json")]
pub use escape_hatches::{NotSensitiveJson, NotSensitiveJsonExt};
#[cfg(feature = "json")]
pub use output::{RedactedJsonExt, RedactedJsonRef};
// Re-export output types
pub use output::{RedactedOutput, RedactedOutputExt, RedactedOutputRef, ToRedactedOutput};
// Re-export redaction machinery
pub use redact::{
    PolicyApplicable, PolicyApplicableRef, RedactableMapper, ScalarRedaction, apply_policy,
    apply_policy_ref, redact,
};
pub use traits::{Redactable, RedactableContainer, RedactableLeaf, RedactableWithPolicy};
// Re-export wrapper types
pub use wrappers::{NotSensitiveValue, SensitiveValue};
