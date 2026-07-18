//! End-to-end tests for the public redaction API.
//!
//! These tests exercise the integration of:
//! - `Sensitive` derive traversal,
//! - policy-bound redaction selection, and
//! - container traversal for common standard library types.

#![allow(clippy::redundant_locals)]

use std::collections::{BTreeMap, HashMap};

use redactable::{
    NotSensitive, NotSensitiveDebugExt, NotSensitiveDisplayExt, NotSensitiveExt, Redactable,
    RedactedOutput, RedactedOutputExt, RedactionPolicy, Secret, Sensitive, SensitiveDisplay,
    SensitiveValue, SensitiveWithPolicy, TextPolicyKind, TextRedactionPolicy, ToRedactedOutput,
    Token,
};

fn log_redacted<T: ToRedactedOutput>(value: &T) -> RedactedOutput {
    value.to_redacted_output()
}

#[path = "integration_basic/container_traversal.rs"]
mod container_traversal;
#[path = "integration_basic/custom_policy.rs"]
mod custom_policy;
#[path = "integration_basic/external_types.rs"]
mod external_types;
#[path = "integration_basic/mixed_fields.rs"]
mod mixed_fields;
#[path = "integration_basic/not_sensitive_attribute.rs"]
mod not_sensitive_attribute;
#[path = "integration_basic/not_sensitive_derive.rs"]
mod not_sensitive_derive;
#[path = "integration_basic/not_sensitive_display_derive.rs"]
mod not_sensitive_display_derive;
#[path = "integration_basic/not_sensitive_escape_hatches.rs"]
mod not_sensitive_escape_hatches;
#[path = "integration_basic/phantom_data.rs"]
mod phantom_data;
#[path = "integration_basic/policy_applicable.rs"]
mod policy_applicable;
#[path = "integration_basic/scalar_redaction.rs"]
mod scalar_redaction;
#[path = "integration_basic/sensitive_derive.rs"]
mod sensitive_derive;
#[path = "integration_basic/sensitive_display_derive.rs"]
mod sensitive_display_derive;
#[path = "integration_basic/text_policy.rs"]
mod text_policy;
#[path = "integration_basic/to_redacted_output.rs"]
mod to_redacted_output;
