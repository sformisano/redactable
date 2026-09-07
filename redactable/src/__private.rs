//! Private compile-time support used by derive-generated policy operations.
//!
//! Field behavior is selected by `RedactionPolicy::Kind`. Text and secret kinds
//! retain recursive compatibility traversal, while IP kinds use a positive,
//! fail-closed structural traversal with safe map-key bounds.

mod declaration;
mod field;
mod formatting;
mod kinds;
mod output;

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

/// Default mapper used by generated private field operations.
pub use crate::redaction::{PolicyFormattingMapper, PolicyMapper};

pub use field::{
    PolicyApplicableRefForFormatting, PolicyApplicableRefForGeneratedFormatting, PolicyField,
    PolicyFieldRef, PolicyFieldRefForFormatting, PolicyKindField, PolicyKindFieldRef,
    PolicyKindFieldRefForFormatting, RecursivePolicyField,
};
pub use formatting::{
    ExplicitLegacyPolicyFormattingRef, GeneratedPolicyFormattingRef, LegacyPolicyFormattingRef,
    PolicyFormattingDispatch, PolicyFormattingProbe, PolicyFormattingRef,
    legacy_policy_formatting_ref, policy_formatting_probe, policy_formatting_ref,
};
pub use kinds::{
    GeneratedPolicyKindDebugFormatting, GeneratedPolicyKindDisplayFormatting,
    PolicyKindDebugFormatting, PolicyKindDisplayFormatting,
};
pub use output::{PolicyFormattingOutput, PolicyRefCellOutput};

/// Constructs generated borrowed slog output without exposing internal constructors.
///
/// The borrowed slog route fails closed to the fixed placeholder, so this takes
/// no argument and builds the value through the crate-private constructor.
#[cfg(feature = "slog")]
#[doc(hidden)]
pub fn generated_redacted_json_placeholder() -> RedactedValue {
    RedactedValue::from_json(Value::String(crate::REDACTED_PLACEHOLDER.to_owned()))
}
