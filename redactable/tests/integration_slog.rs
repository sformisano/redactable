//! Integration tests for the slog module.
//!
//! These tests verify that:
//! - `slog_redacted_json()` produces correctly redacted JSON values
//! - The `slog::Value` implementation works with slog's serialization API
//! - Nested structures are properly redacted when logged

#![cfg(feature = "slog")]

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex},
};

use redactable::{
    Email, IntoRedactedOutputExt, NotSensitiveJsonExt, PhoneNumber, Pii, Redactable,
    RedactableMapper, RedactableWithFormatter, RedactableWithMapper, RedactedJsonExt,
    RedactedOutput, RedactedOutputExt, RedactionPolicy, Secret, Sensitive, SensitiveDisplay,
    SensitiveValue, TextPolicyKind, TextRedactionPolicy, ToRedactedOutput, Token,
    slog::{SlogRedacted, SlogRedactedExt},
};
use redactable_test_fixtures::GenericDualFixture;
use serde::Serialize;
use slog::{Drain as _, KV as _};

#[path = "support/slog_capture.rs"]
pub(crate) mod slog_capture;

use slog_capture::{CapturedValue, CapturingSerializer, serialize_to_capture};

#[derive(Clone)]
struct CapturingDrain {
    captured: Arc<Mutex<Vec<CapturedValue>>>,
}

impl slog::Drain for CapturingDrain {
    type Ok = ();
    type Err = slog::Never;

    fn log(
        &self,
        record: &slog::Record<'_>,
        values: &slog::OwnedKVList,
    ) -> Result<Self::Ok, Self::Err> {
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

fn capturing_logger() -> (slog::Logger, Arc<Mutex<Vec<CapturedValue>>>) {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let drain = CapturingDrain {
        captured: Arc::clone(&captured),
    }
    .fuse();
    (slog::Logger::root(drain, slog::o!()), captured)
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
    slog::info!(logger, "owned"; "event" => owned.into_redacted_output());
    let emitted = format!("{:?}", captured.lock().expect("capture lock").as_slice());
    assert!(emitted.contains("[REDACTED]"));
    assert!(!emitted.contains(CANARY));

    let borrowed = Event {
        secret: RefCell::new(CANARY.to_owned()),
    };
    let _borrow = borrowed.secret.borrow_mut();
    let result = catch_unwind(AssertUnwindSafe(|| {
        slog::info!(logger, "borrowed"; "event" => borrowed.redacted_output());
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
        Some(CapturedValue::Serde(serde_json::Value::String(
            String::from("[REDACTED]")
        )))
    );
}

fn log_redacted<T: ToRedactedOutput>(value: &T) -> RedactedOutput {
    value.to_redacted_output()
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
