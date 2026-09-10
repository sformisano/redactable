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

use redactable::{RedactedValue, Secret, Sensitive, ToRedacted};
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

fn log_redacted<T: ToRedacted>(value: &T) -> RedactedValue {
    value.to_redacted()
}

#[test]
fn display_adapter_emits_selected_text_and_json_through_real_drain() {
    use std::fmt::{Formatter, Result as FmtResult};

    use redactable::{
        BypassJsonRedaction, BypassTextRedaction, RedactableWithFormatter, slog::SlogRedactedExt,
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
                BypassTextRedaction("SELECTED".to_owned()).to_redacted()
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
