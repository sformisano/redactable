//! Private compile-time support used by derive-generated policy operations.
//!
//! Field behavior is selected by `RedactionPolicy::Kind`. Text and secret kinds
//! retain recursive compatibility traversal, while IP kinds use a positive,
//! fail-closed structural traversal with safe map-key bounds.

mod declaration;
mod field;
mod formatting;
mod kinds;

#[cfg(feature = "slog")]
use crate::RedactedValue;
#[cfg(feature = "slog")]
use serde_json::Value;

pub use declaration::{
    DeclaredFormatting, DeclaredNotSensitive, require_declared_formatting,
    require_declared_redaction,
};

#[doc(hidden)]
pub use crate::redaction::{IpPolicyApplicable, IpPolicyApplicableRef};

/// Fail-closed JSON serialization used by redacted logging adapters.
pub use crate::redaction::serialize_redacted_json;
/// Sink-value construction reserved for derive-generated producers.
///
/// Each helper redacts or serializes a value whose type carries the matching
/// declaration; none of them accepts a raw payload.
pub use crate::redaction::{
    generated_declared_json, generated_redacted_display, generated_redacted_dual,
    generated_redacted_json,
};
/// Serialization support used by derive-generated implementations.
pub use serde;
/// JSON support used by derive-generated slog implementations.
#[cfg(feature = "slog")]
pub use serde_json;
/// Logging support used by derive-generated slog implementations.
#[cfg(feature = "slog")]
pub use slog;

// Cargo can share one host proc macro between runtime crates with different
// features. Resolve these gates through the runtime that each derive uses.
#[doc(hidden)]
#[macro_export]
macro_rules! __redactable_include_impls {
    ($($implementation:item)*) => { $($implementation)* };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __redactable_omit_impls {
    ($($implementation:item)*) => {};
}

#[cfg(feature = "slog")]
pub use crate::__redactable_include_impls as with_slog;
#[cfg(feature = "tracing")]
pub use crate::__redactable_include_impls as with_tracing;
#[cfg(not(feature = "slog"))]
pub use crate::__redactable_omit_impls as with_slog;
#[cfg(not(feature = "tracing"))]
pub use crate::__redactable_omit_impls as with_tracing;

/// Default mapper used by generated private field operations.
pub use crate::redaction::{PolicyFormattingMapper, PolicyMapper};

/// Public since the formatting trait became the custom-leaf extension point;
/// re-exported here for generated code that still addresses it privately.
pub use crate::redaction::PolicyFormattingOutput;
pub use field::{PolicyField, PolicyFieldRef, PolicyKindField, PolicyKindFieldRef};
pub use formatting::{PolicyFormattingRef, policy_formatting_ref};
pub use kinds::{PolicyKindDebugFormatting, PolicyKindDisplayFormatting};

/// Constructs generated borrowed slog output without exposing internal constructors.
///
/// The borrowed slog route fails closed to the fixed placeholder, so this takes
/// no argument and builds the value through the crate-private constructor.
#[cfg(feature = "slog")]
#[doc(hidden)]
pub fn generated_redacted_json_placeholder() -> RedactedValue {
    RedactedValue::from_json(Value::String(crate::REDACTED_PLACEHOLDER.to_owned()))
}
