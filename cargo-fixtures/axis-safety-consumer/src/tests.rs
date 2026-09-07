use std::panic::catch_unwind;

use redactable::{
    BypassDebugRedaction, BypassDisplayRedaction, BypassJsonRedaction, BypassTextRedaction,
    Redactable, RedactableWithFormatter, RedactedValue, ToRedacted,
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    capture::capture_fields,
    logging::{audit_display, axis_fields, field_typed},
    models::{
        AccountId, DivergentOutput, DualOutput, EndpointError, EventSummary, ForeignError,
        ForeignPublic, FullMaskLogView, FullMaskOutput, OwnershipOutput, StructuralInput,
    },
    selected_contracts::{
        AccountDetailsValidation, AccountOwnership, AccountView, CapabilitySummary, OwnerLookup,
        RecordedDecision, SerializationFailure,
    },
};

fn ownership() -> OwnershipOutput {
    OwnershipOutput {
        owner_name: "Ada".to_owned(),
        approved: true,
    }
}

fn input() -> StructuralInput {
    StructuralInput {
        account_id: AccountId::new("raw-account-id"),
        owner_name: "Ada".to_owned(),
        request_kind: "public-request",
    }
}

#[test]
fn selected_json_and_foreign_escapes_reach_the_real_tracing_visitor() {
    let output = ownership();
    let public = ForeignPublic {
        status: "ready",
        attempt: 7,
    };
    let captured = capture_fields(axis_fields!(
        typed = @output,
        display = %output,
        debug = ?output,
        public_json = @BypassJsonRedaction(&public),
        public_display = %BypassDisplayRedaction(&public),
        public_debug = ?BypassDebugRedaction(&public),
        plain = %BypassDisplayRedaction("plain public string")
    ));
    // Independent values and complete key set: never ask the producer for a golden.
    assert_eq!(
        captured,
        json!({
            "typed": {"owner_name": "[REDACTED]", "approved": true},
            "display": "{\"approved\":true,\"owner_name\":\"[REDACTED]\"}",
            "debug": "{\"approved\":true,\"owner_name\":\"[REDACTED]\"}",
            "public_json": {"status": "ready", "attempt": 7},
            "public_display": "ready",
            "public_debug": "ForeignPublic { status: \"ready\", attempt: 7 }",
            "plain": "plain public string",
        })
    );
}

#[test]
fn structural_input_uses_private_nominal_id_and_preserves_raw_transport() {
    let input = input();
    assert_eq!(
        capture_fields(axis_fields!(input = input)),
        json!({
            "input": {
                "account_id": "<redacted-aggregate-id>",
                "owner_name": "[REDACTED]",
                "request_kind": "public-request",
            }
        })
    );
    assert_eq!(
        serde_json::to_value(&input).unwrap(),
        json!({
            "account_id": "raw-account-id", "owner_name": "Ada", "request_kind": "public-request",
        })
    );
    assert_eq!(
        serde_json::to_value(ownership()).unwrap(),
        json!({
            "owner_name": "Ada", "approved": true,
        })
    );
}

#[test]
fn nominal_companion_and_omitted_foreign_sources_keep_exact_text() {
    let summary = EventSummary {
        account_id: AccountId::new("id-canary"),
        omitted_source: ForeignError("source-canary".to_owned()),
    };
    let error = EndpointError {
        source: ForeignError("error-canary".to_owned()),
    };
    assert_eq!(
        summary.account_id.redacted_display().to_string(),
        "<redacted-aggregate-id>"
    );
    assert_eq!(summary.omitted_source.0, "source-canary");
    assert_eq!(error.source.0, "error-canary");
    assert_eq!(
        capture_fields(axis_fields!(summary = @summary, error = %error,)),
        json!({
            "summary": {"message": "account_id=<redacted-aggregate-id>"},
            "error": "account command failed",
        })
    );
    assert_eq!(
        audit_display(&summary),
        "account_id=<redacted-aggregate-id>"
    );
    assert_eq!(audit_display(&error), "account command failed");
}

#[test]
fn selected_producer_wins_over_dual_template_and_divergent_formatter() {
    let dual = DualOutput {
        owner_name: "Ada".to_owned(),
        approved: true,
    };
    assert_eq!(dual.redacted_display().to_string(), "owner=[REDACTED]");
    assert_eq!(DivergentOutput.redacted_display().to_string(), "FORMATTER");
    assert_eq!(
        capture_fields(axis_fields!(
            typed = @dual, display = %dual, debug = ?dual,
            divergent_display = %DivergentOutput, divergent_debug = ?DivergentOutput,
            divergent_typed = @DivergentOutput,
        )),
        json!({
            // A dual carries both: `@` reads its JSON, `%`/`?` its template.
            "typed": {"owner_name": "[REDACTED]", "approved": true},
            "display": "owner=[REDACTED]",
            "debug": "owner=[REDACTED]",
            "divergent_display": "SELECTED", "divergent_debug": "SELECTED",
            // A text-only producer under `@` is read as JSON through the
            // documented fallback, not as a bare JSON string.
            "divergent_typed": {"message": "SELECTED"},
        })
    );
    // D10: the audit path renders `text()`. A dual value has template text; a
    // JSON-only producer renders as compact JSON text.
    assert_eq!(audit_display(&dual), "owner=[REDACTED]");
    assert_eq!(
        audit_display(&ownership()),
        "{\"approved\":true,\"owner_name\":\"[REDACTED]\"}"
    );
}

#[test]
fn transparent_owner_lookup_preserves_none_some_and_empty_some() {
    for (raw, expected, text) in [
        (None, Value::Null, "null"),
        (
            Some("Alice".to_owned()),
            json!("[REDACTED:owner]"),
            "\"[REDACTED:owner]\"",
        ),
        (
            Some(String::new()),
            json!("[REDACTED:owner]"),
            "\"[REDACTED:owner]\"",
        ),
    ] {
        let lookup = OwnerLookup(raw.clone());
        assert_eq!(
            capture_fields(axis_fields!(typed = @lookup, display = %lookup, debug = ?lookup,)),
            json!({"typed": expected, "display": text, "debug": text})
        );
        assert_eq!(serde_json::to_value(&lookup).unwrap(), json!(raw));
        assert_eq!(lookup.clone().into_inner(), raw);
        assert_eq!(audit_display(&lookup), text);
    }
}

#[test]
fn deliberate_summaries_suppress_canaries_and_option_presence() {
    for present in [false, true] {
        let decision = RecordedDecision(present.then(|| "decision-canary".to_owned()));
        let ownership = AccountOwnership(present.then(|| AccountView {
            owner: "owner-canary".to_owned(),
            funds: 9182,
            version: 73,
        }));
        let details = AccountDetailsValidation("details-canary".to_owned());
        assert_eq!(decision.0.is_some(), present);
        assert_eq!(ownership.0.is_some(), present);
        assert_eq!(details.0, "details-canary");
        assert_eq!(
            capture_fields(axis_fields!(
                decision = @decision, ownership = @ownership, details = @details,
            )),
            json!({
                "decision": {"message": "[REDACTED:recorded-decision]"},
                "ownership": {"message": "[REDACTED:account-ownership]"},
                "details": {"message": "[REDACTED:account-details-validation]"},
            })
        );
    }
    for allowed in [false, true] {
        let summary = CapabilitySummary { value: 42, allowed };
        assert_eq!(
            capture_fields(axis_fields!(capability = @summary)),
            json!({"capability": {"message": "value=42"}})
        );
        assert_eq!(
            serde_json::to_value(summary).unwrap(),
            json!({"value": 42, "allowed": allowed})
        );
    }
    let empty = BypassTextRedaction(String::new());
    assert_eq!(
        capture_fields(axis_fields!(summary = @empty)),
        json!({"summary": {"message": ""}})
    );
}

#[test]
fn full_selected_mask_does_not_expand_to_structural_pii() {
    let output = FullMaskOutput {
        account_id: AccountId::new("id-canary"),
        owner_name: "Alice".to_owned(),
    };
    assert_eq!(
        capture_fields(axis_fields!(result = @FullMaskLogView::from(&output))),
        json!({
            "result": {"account_id": "<redacted-aggregate-id>", "owner_name": "[REDACTED]"},
        })
    );
    assert_eq!(
        capture_fields(axis_fields!(input = output)),
        json!({
            "input": {"account_id": "<redacted-aggregate-id>", "owner_name": "***ce"},
        })
    );
    assert_eq!(
        serde_json::to_value(output).unwrap(),
        json!({
            "account_id": "id-canary", "owner_name": "Alice",
        })
    );
}

fn assert_structured_result<T: ToRedacted>(output: &T) {
    assert_eq!(
        capture_fields(axis_fields!(result = @*output)),
        json!({
            "result": {"owner_name": "[REDACTED]", "approved": true},
        })
    );
}

enum BadProducer {
    Blank,
    WholePlaceholder,
    MissingField,
}

impl ToRedacted for BadProducer {
    fn to_redacted(&self) -> RedactedValue {
        match self {
            Self::Blank => BypassTextRedaction(String::new()).to_redacted(),
            Self::WholePlaceholder => BypassJsonRedaction(&"[REDACTED]").to_redacted(),
            Self::MissingField => {
                BypassJsonRedaction(&json!({"owner_name": "[REDACTED]"})).to_redacted()
            }
        }
    }
}

#[test]
fn same_structured_assertion_rejects_blank_whole_placeholder_and_missing_field() {
    assert_structured_result(&ownership());
    for bad in [
        BadProducer::Blank,
        BadProducer::WholePlaceholder,
        BadProducer::MissingField,
    ] {
        assert!(catch_unwind(|| assert_structured_result(&bad)).is_err());
    }
}

#[test]
fn serialization_failure_is_checked_separately_from_structured_success() {
    assert!(serde_json::to_value(SerializationFailure).is_err());
    assert_eq!(
        capture_fields(axis_fields!(result = @SerializationFailure)),
        json!({"result": "[REDACTED]"})
    );
    assert_eq!(
        capture_fields(axis_fields!(input = SerializationFailure)),
        json!({"input": null})
    );
    assert_eq!(audit_display(&SerializationFailure), "\"[REDACTED]\"");
}

// Exact relevant bounds from Axis's effect/mod.rs and action/contracts.rs,
// revision 14417ae77286e45a7d4dbbd8e674a9a6cc091397. Framework contexts, errors
// and execution are outside this bounded output-consumer fixture.
fn effect_result<I, O>(_: &I, output: O) -> Value
where
    I: Redactable + Serialize + Clone + Send + 'static,
    O: ToRedacted + Send + 'static,
{
    field_typed(&output)
}

fn action_result<I, O>(_: &I, output: O) -> Value
where
    I: Sized + Send + Clone + Serialize + Redactable + 'static,
    O: ToRedacted + Send + 'static,
{
    field_typed(&output)
}

#[test]
fn effect_and_action_bounds_accept_display_only_and_foreign_public_outputs() {
    static PUBLIC: ForeignPublic = ForeignPublic {
        status: "ready",
        attempt: 7,
    };
    let input = input();
    let display_only = || EndpointError {
        source: ForeignError("canary".to_owned()),
    };
    let expected_command = json!({"message": "account command failed"});
    assert_eq!(effect_result(&input, display_only()), expected_command);
    assert_eq!(action_result(&input, display_only()), expected_command);
    assert_eq!(
        effect_result(&input, BypassDisplayRedaction(&PUBLIC)),
        json!({"message": "ready"})
    );
    assert_eq!(
        action_result(&input, BypassDisplayRedaction(&PUBLIC)),
        json!({"message": "ready"})
    );
    let expected_debug = json!({
        "message": "ForeignPublic { status: \"ready\", attempt: 7 }"
    });
    assert_eq!(
        effect_result(&input, BypassDebugRedaction(&PUBLIC)),
        expected_debug
    );
    assert_eq!(
        action_result(&input, BypassDebugRedaction(&PUBLIC)),
        expected_debug
    );
    assert_eq!(
        effect_result(&input, BypassJsonRedaction(&PUBLIC)),
        json!({"status": "ready", "attempt": 7})
    );
    assert_eq!(
        action_result(&input, BypassJsonRedaction(&PUBLIC)),
        json!({"status": "ready", "attempt": 7})
    );
    assert_eq!(
        effect_result(&input, BypassDisplayRedaction("plain public string")),
        json!({"message": "plain public string"})
    );
    assert_eq!(
        action_result(&input, BypassDisplayRedaction("plain public string")),
        json!({"message": "plain public string"})
    );
}
