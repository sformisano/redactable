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
use crate::RedactedJson;
#[cfg(feature = "slog")]
use serde_json::Value;

pub use declaration::{
    DeclaredFormatting, require_declared_formatting, require_declared_redaction,
};

/// Emits a generated JSON producer only when the runtime has JSON support.
#[cfg(feature = "json")]
#[doc(hidden)]
#[macro_export]
macro_rules! __redactable_generated_json_output {
    ($($items:item)*) => { $($items)* };
}

/// Reports a missing runtime feature without resolving JSON-only items.
#[cfg(not(feature = "json"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __redactable_generated_json_output {
    ($($items:item)*) => {
        ::core::compile_error!("`#[redactable(output = json)]` requires redactable's `json` feature; enable that feature on the runtime dependency");
    };
}

pub use crate::__redactable_generated_json_output as generated_json_output;

#[doc(hidden)]
pub use crate::redaction::{IpPolicyApplicable, IpPolicyApplicableRef};

/// Fail-closed JSON serialization used by redacted logging adapters.
#[cfg(feature = "json")]
pub use crate::redaction::serialize_redacted_json;
/// Serialization support used by derive-generated slog implementations.
#[cfg(feature = "json")]
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
#[cfg(feature = "slog")]
#[doc(hidden)]
pub fn generated_redacted_json_placeholder() -> RedactedJson {
    RedactedJson::new(Value::String(crate::REDACTED_PLACEHOLDER.to_owned()))
}
