//! Redaction traversal and entrypoints.
//!
//! This module provides the machinery for applying redaction:
//!
//! - **`traits`**: Core traits (`RedactableWithMapper`, `SensitiveWithPolicy`, `Redactable`)
//! - **`redact`**: Application layer - the redaction machinery (`PolicyApplicable`, `RedactableMapper`)
//! - **`wrappers`**: Wrapper types (`SensitiveValue`, `BypassRedaction`)
//! - **`output`**: The logging-boundary sink value (`RedactedValue`, `ToRedacted`)
//! - **`display`**: Redacted display support (`RedactableWithFormatter`, `RedactedFormatterRef`)
//! - **`escape_hatches`**: The Bypass family for deliberately non-redacted values
//! - **`containers`**: `RedactableWithMapper` implementations for std types
//!
//! Policy marker types and text policies live in `crate::policy`.

mod containers;
mod display;
mod escape_hatches;
mod ip_policy;
mod json;
mod list;
mod output;
pub mod redact;
mod traits;
mod wrappers;

// Re-export core traits
// Re-export display types
pub use display::{PolicyRedactedFormatterRef, RedactableWithFormatter, RedactedFormatterRef};
// Re-export the Bypass family
pub use escape_hatches::{
    BypassDebugRedaction, BypassDisplayRedaction, BypassJsonRedaction, BypassRedactionMarker,
    BypassTextRedaction,
};
pub use list::RedactedList;
// Re-export the sink value and its producer trait
pub use output::{
    RedactedValue, ToRedacted, generated_declared_json, generated_redacted_display,
    generated_redacted_dual, generated_redacted_json, serialize_redacted_json,
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
pub use wrappers::{BypassRedaction, SensitiveValue};
