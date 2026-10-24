//! Integration tests for the slog module.
//!
//! These tests verify that:
//! - `slog_redacted_json()` produces correctly redacted JSON values
//! - The `slog::Value` implementation works with slog's serialization API
//! - Nested structures are properly redacted when logged

#![cfg(feature = "slog")]

use std::{
    cell::RefCell,
    collections::BTreeMap,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex},
};

use redactable::{RedactedValue, Secret, Sensitive, ToRedacted, slog::SlogRedactedExt};
use redactable_test_fixtures::GenericDualFixture;
use serde::Serialize;
use serde_json::Value as JsonValue;
use slog::{Drain, KV as _, Logger, Never, OwnedKVList, Record};

#[path = "support/slog_capture.rs"]
pub(crate) mod slog_capture;

use slog_capture::{CapturedValue, CapturingSerializer, serialize_to_capture};

#[derive(Clone)]
struct CapturingDrain {
    captured: Arc<Mutex<Vec<CapturedValue>>>,
}

impl Drain for CapturingDrain {
    type Ok = ();
    type Err = Never;

    fn log(&self, record: &Record<'_>, values: &OwnedKVList) -> Result<Self::Ok, Self::Err> {
        let mut serializer = CapturingSerializer::new();
        record
            .kv()
            .serialize(record, &mut serializer)
            .expect("record values serialize");
        values
            .serialize(record, &mut serializer)
            .expect("logger values serialize");
        if let Some(value) = serializer.get("event") {
            self.captured
                .lock()
                .expect("capturing drain lock")
                .push(value);
        }
        Ok(())
    }
}

fn capturing_logger() -> (Logger, Arc<Mutex<Vec<CapturedValue>>>) {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let drain = CapturingDrain {
        captured: Arc::clone(&captured),
    }
    .fuse();
    (Logger::root(drain, slog::o!()), captured)
}

#[test]
fn useful_execution_and_review_context_reaches_real_drain_with_nested_secrets_protected() {
    #[derive(Clone, Serialize, Sensitive)]
    struct ReviewSnapshot {
        #[not_sensitive]
        version: u64,
        #[not_sensitive]
        title: String,
        #[not_sensitive]
        commit_message: String,
        #[not_sensitive]
        branch: String,
        #[not_sensitive]
        labels: Vec<String>,
        #[not_sensitive]
        paths: Vec<String>,
        #[not_sensitive]
        count: u32,
        #[not_sensitive]
        status: String,
        #[sensitive(Secret)]
        access_token: String,
    }

    #[derive(Clone, Serialize, Sensitive)]
    struct ReviewExecution {
        #[not_sensitive]
        request_id: String,
        #[not_sensitive]
        event_id: String,
        #[not_sensitive]
        step_id: String,
        #[not_sensitive]
        run_id: String,
        #[not_sensitive]
        schedule_id: String,
        #[not_sensitive]
        actor_id: u64,
        #[sensitive(Secret)]
        actor_email: String,
        before: Option<ReviewSnapshot>,
        after: ReviewSnapshot,
    }

    let event = ReviewExecution {
        request_id: "request/review-42".into(),
        event_id: "event/commit-73".into(),
        step_id: "review:publish-findings".into(),
        run_id: "run/nightly-14".into(),
        schedule_id: "schedule/platform-nightly".into(),
        actor_id: 17,
        actor_email: "personal-contact-canary@example.invalid".into(),
        before: Some(ReviewSnapshot {
            version: 3,
            title: "Draft: improve routing".into(),
            commit_message: "fix(routing): preserve branch context\n\nExplain the selected target."
                .into(),
            branch: "feature/review-context".into(),
            labels: vec!["workflow::triage".into()],
            paths: vec!["src/old_route.rs".into()],
            count: 1,
            status: "queued".into(),
            access_token: "before-credential-canary".into(),
        }),
        after: ReviewSnapshot {
            version: 4,
            title: "Improve routing / 路由".into(),
            commit_message: "fix(routing): preserve branch context\n\nExplain the selected target."
                .into(),
            branch: "release/next".into(),
            labels: vec!["workflow::ready".into(), "component::routing".into()],
            paths: vec!["src/route.rs".into(), "docs/review.md".into()],
            count: 2,
            status: "awaiting_policy_sync".into(),
            access_token: "after-credential-canary".into(),
        },
    };
    let original = serde_json::to_value(&event).unwrap();
    let expected = serde_json::json!({
        "request_id": "request/review-42", "event_id": "event/commit-73",
        "step_id": "review:publish-findings", "run_id": "run/nightly-14",
        "schedule_id": "schedule/platform-nightly", "actor_id": 17,
        "actor_email": "[REDACTED]",
        "before": {
            "version": 3, "title": "Draft: improve routing",
            "commit_message": "fix(routing): preserve branch context\n\nExplain the selected target.",
            "branch": "feature/review-context", "labels": ["workflow::triage"],
            "paths": ["src/old_route.rs"], "count": 1, "status": "queued",
            "access_token": "[REDACTED]"
        },
        "after": {
            "version": 4, "title": "Improve routing / 路由",
            "commit_message": "fix(routing): preserve branch context\n\nExplain the selected target.",
            "branch": "release/next", "labels": ["workflow::ready", "component::routing"],
            "paths": ["src/route.rs", "docs/review.md"], "count": 2, "status": "awaiting_policy_sync",
            "access_token": "[REDACTED]"
        }
    });
    let (logger, captured) = capturing_logger();
    slog::info!(logger, "review projection"; "event" => event.slog_redacted_json());
    slog::info!(logger, "review producer"; "event" => event.to_redacted());
    slog::info!(logger, "opaque borrowed event"; "event" => &event);

    let values = captured.lock().unwrap();
    assert_eq!(
        *values,
        [
            CapturedValue::Serde(expected.clone()),
            CapturedValue::Serde(expected),
            CapturedValue::Serde(serde_json::json!("[REDACTED]")),
        ]
    );
    let output = format!("{values:?}");
    for secret in [
        "before-credential-canary",
        "after-credential-canary",
        "personal-contact-canary@example.invalid",
    ] {
        assert!(!output.contains(secret));
    }
    assert_eq!(serde_json::to_value(&event).unwrap(), original);
    assert_eq!(event.after.access_token, "after-credential-canary");
    assert_eq!(
        original["before"]["access_token"],
        "before-credential-canary"
    );
    assert_eq!(
        original["actor_email"],
        "personal-contact-canary@example.invalid"
    );
}

#[test]
fn typed_projection_of_erased_input_keeps_review_context_without_promoting_raw_json() {
    #[derive(Clone, serde::Deserialize, Serialize, Sensitive)]
    struct ReviewContext {
        #[not_sensitive]
        title: String,
        #[not_sensitive]
        message: String,
        #[not_sensitive]
        branch: String,
        #[not_sensitive]
        labels: Vec<String>,
        #[not_sensitive]
        paths: Vec<String>,
        #[not_sensitive]
        count: u32,
        #[not_sensitive]
        status: String,
    }

    #[derive(Clone, serde::Deserialize, Serialize, Sensitive)]
    struct SelectedInput {
        #[not_sensitive]
        request_id: String,
        #[not_sensitive]
        event_id: String,
        review: ReviewContext,
    }

    let raw = serde_json::json!({
        "request_id": "request/erased-19", "event_id": "event/review-19",
        "review": {
            "title": "Keep implementation context", "message": "Explain the branch transition.",
            "branch": "feature/typed-projection", "labels": ["review::ready"],
            "paths": ["src/review.rs"], "count": 1, "status": "accepted",
            "access_token": "nested-erased-token-canary"
        },
        "access_token": "erased-token-canary", "personal_email": "erased-person-canary@example.invalid"
    });
    let original = raw.clone();
    let selected: SelectedInput = serde_json::from_value(raw.clone()).unwrap();
    let expected = serde_json::json!({
        "request_id": "request/erased-19", "event_id": "event/review-19",
        "review": {
            "title": "Keep implementation context", "message": "Explain the branch transition.",
            "branch": "feature/typed-projection", "labels": ["review::ready"],
            "paths": ["src/review.rs"], "count": 1, "status": "accepted"
        }
    });
    let (logger, captured) = capturing_logger();
    slog::info!(logger, "selected review context"; "event" => selected.slog_redacted_json());
    let values = captured.lock().unwrap();
    assert_eq!(*values, [CapturedValue::Serde(expected.clone())]);
    assert_eq!(serde_json::to_value(&selected).unwrap(), expected);
    let output = format!("{values:?}");
    for secret in [
        "erased-token-canary",
        "nested-erased-token-canary",
        "erased-person-canary@example.invalid",
    ] {
        assert!(!output.contains(secret));
    }
    assert_eq!(raw, original);
    assert_eq!(raw["access_token"], "erased-token-canary");
    assert_eq!(raw["review"]["access_token"], "nested-erased-token-canary");
}

#[test]
fn real_slog_drain_keeps_canary_out_and_documents_borrowed_clone_panic() {
    #[derive(Clone, Sensitive, Serialize)]
    struct Event {
        #[sensitive(Secret)]
        secret: RefCell<String>,
    }

    const CANARY: &str = "round3-slog-drain-canary";
    let (logger, captured) = capturing_logger();
    let owned = Event {
        secret: RefCell::new(CANARY.to_owned()),
    };
    slog::info!(logger, "owned"; "event" => owned.to_redacted());
    let emitted = format!("{:?}", captured.lock().expect("capture lock").as_slice());
    assert!(emitted.contains("[REDACTED]"));
    assert!(!emitted.contains(CANARY));

    let borrowed = Event {
        secret: RefCell::new(CANARY.to_owned()),
    };
    let _borrow = borrowed.secret.borrow_mut();
    let result = catch_unwind(AssertUnwindSafe(|| {
        slog::info!(logger, "borrowed"; "event" => borrowed.to_redacted());
    }));
    assert!(result.is_err());
}

#[test]
fn genuine_generic_dual_generated_slog_omits_canary() {
    const CANARY: &str = "generic-dual-slog-canary-86d2";
    let value = GenericDualFixture {
        label: String::from("event"),
        secret: String::from(CANARY),
    };
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&value, "value", &mut serializer);
    let captured = format!("{:?}", serializer.get("value"));
    assert!(captured.contains("[REDACTED]"));
    assert!(!captured.contains(CANARY));
}

#[test]
fn concrete_borrow_sensitive_map_key_slog_emits_placeholder_without_cloning() {
    #[derive(Clone, Sensitive, Serialize)]
    struct Event {
        #[not_sensitive]
        records: BTreeMap<RefCell<String>, String>,
    }

    let event = Event {
        records: BTreeMap::from([(RefCell::new(String::from("key")), String::from("value"))]),
    };
    let _borrow = event.records.keys().next().unwrap().borrow_mut();
    let mut serializer = CapturingSerializer::new();

    serialize_to_capture(&event, "event", &mut serializer);

    assert_eq!(
        serializer.get("event"),
        Some(CapturedValue::Serde(JsonValue::String(String::from(
            "[REDACTED]"
        ))))
    );
}

#[test]
fn unsized_producer_slog_json_matches_concrete_output() {
    #[derive(Clone, Sensitive, Serialize)]
    struct Event {
        #[not_sensitive]
        label: String,
        #[sensitive(Secret)]
        token: String,
    }

    const CANARY: &str = "unsized-slog-adapter-canary";
    let event = Event {
        label: "login".to_owned(),
        token: CANARY.to_owned(),
    };
    let producer: &dyn ToRedacted = &event;
    let concrete = event.slog_redacted_json();
    let dynamic = producer.slog_redacted_json();
    let expected = CapturedValue::Serde(serde_json::json!({
        "label": "login",
        "token": "[REDACTED]",
    }));

    let mut concrete_capture = CapturingSerializer::new();
    serialize_to_capture(&concrete, "event", &mut concrete_capture);
    let mut dynamic_capture = CapturingSerializer::new();
    serialize_to_capture(&dynamic, "event", &mut dynamic_capture);

    assert_eq!(concrete_capture.get("event"), Some(expected.clone()));
    assert_eq!(dynamic_capture.get("event"), Some(expected));
    assert!(!format!("{:?}", dynamic_capture.get("event")).contains(CANARY));
}

fn log_redacted<T: ToRedacted>(value: &T) -> RedactedValue {
    value.to_redacted()
}

#[test]
fn composed_producers_preserve_text_and_structured_output_through_real_drain() {
    const CANARY: &str = "slog-producer-composition-private-8234";
    let text = Some(Box::new(redactable::SensitiveValue::<_, Secret>::from(
        CANARY.to_owned(),
    )));
    let dual = Some(Arc::new(GenericDualFixture {
        label: "account",
        secret: CANARY.to_owned(),
    }));
    let (logger, captured) = capturing_logger();
    slog::info!(logger, "text"; "event" => log_redacted(&text));
    slog::info!(logger, "dual"; "event" => log_redacted(&dual));
    slog::info!(logger, "absent"; "event" => log_redacted(&None::<()>));
    slog::info!(logger, "unit"; "event" => log_redacted(&()));
    let values = captured.lock().expect("capture lock");
    assert_eq!(
        *values,
        [
            CapturedValue::Str("[REDACTED]".into()),
            CapturedValue::Serde(serde_json::json!({"label": "account", "secret": "[REDACTED]"})),
            CapturedValue::Serde(JsonValue::Null),
            CapturedValue::Serde(JsonValue::Null),
        ]
    );
    assert!(!format!("{values:?}").contains(CANARY));
}

#[test]
fn display_adapter_emits_selected_text_and_json_through_real_drain() {
    use std::fmt::{Formatter, Result as FmtResult};

    use redactable::{
        BypassDisplayRedaction, BypassJsonRedaction, RedactableWithFormatter, slog::SlogRedactedExt,
    };

    struct Divergent {
        json: bool,
    }

    impl RedactableWithFormatter for Divergent {
        fn fmt_redacted(&self, f: &mut Formatter<'_>) -> FmtResult {
            f.write_str("FORMATTER")
        }
    }

    impl ToRedacted for Divergent {
        fn to_redacted(&self) -> RedactedValue {
            if self.json {
                BypassJsonRedaction(
                    &serde_json::json!({"approved": true, "owner_name": "[REDACTED]"}),
                )
                .to_redacted()
            } else {
                BypassDisplayRedaction("SELECTED".to_owned()).to_redacted()
            }
        }
    }

    let (logger, captured) = capturing_logger();
    let text = Divergent { json: false };
    let json = Divergent { json: true };
    assert_eq!(text.redacted_display().to_string(), "FORMATTER");
    slog::info!(logger, "selected text"; "event" => text.slog_redacted());
    slog::info!(logger, "selected JSON text"; "event" => json.slog_redacted());
    assert_eq!(
        *captured.lock().expect("capture lock"),
        vec![
            CapturedValue::Str("SELECTED".to_owned()),
            CapturedValue::Str("{\"approved\":true,\"owner_name\":\"[REDACTED]\"}".to_owned()),
        ]
    );
}

#[path = "integration_slog/marker_trait.rs"]
mod marker_trait;
#[path = "integration_slog/not_sensitive_json.rs"]
mod not_sensitive_json;
#[path = "integration_slog/redacted_json.rs"]
mod redacted_json;
#[path = "integration_slog/sensitive_display.rs"]
mod sensitive_display;
#[path = "integration_slog/sensitive_value.rs"]
mod sensitive_value;
#[path = "integration_slog/slog_redacted_json.rs"]
mod slog_redacted_json;
