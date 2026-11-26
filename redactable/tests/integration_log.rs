//! Structured fields delivered to a `log` backend.

#![cfg(feature = "log")]

use std::{cell::Cell, collections::BTreeMap, sync::OnceLock};

use log::{
    LevelFilter, Log, Metadata, Record,
    kv::{Error, Key, Value, VisitSource},
};
use redactable::log::LogRedactedExt;
use redactable::{
    BypassJsonRedaction, RedactedValue, Secret, Sensitive, SensitiveDual, SensitiveValue,
    ToRedacted,
};
use redactable_test_fixtures::{FixtureUser, GenericDualFixture};
use serde::{Serialize, Serializer, ser::Error as _, ser::SerializeMap};
use serde_json::{Map, Value as JsonValue, json};

const RAW_TOKEN: &str = "private-log-token-2705";

#[derive(Default)]
struct Fields(Map<String, JsonValue>);

impl<'kvs> VisitSource<'kvs> for Fields {
    fn visit_pair(&mut self, key: Key<'kvs>, value: Value<'kvs>) -> Result<(), Error> {
        self.0.insert(
            key.as_str().to_owned(),
            serde_json::to_value(value).unwrap(),
        );
        Ok(())
    }
}

struct Capture(OnceLock<JsonValue>);

impl Log for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &Record<'_>) {
        let mut fields = Fields::default();
        record.key_values().visit(&mut fields).unwrap();
        self.0.set(JsonValue::Object(fields.0)).unwrap();
    }

    fn flush(&self) {}
}

fn capture(emit: impl FnOnce(&Capture)) -> JsonValue {
    log::set_max_level(LevelFilter::Info);
    let logger = Capture(OnceLock::new());
    emit(&logger);
    logger.0.into_inner().expect("one log record")
}

#[test]
fn record_keeps_nested_objects_arrays_and_map_key_policy() {
    #[derive(Clone, Sensitive, Serialize)]
    struct Account {
        members: Vec<Option<FixtureUser>>,
        #[sensitive(Secret)]
        sessions: BTreeMap<String, String>,
    }

    const RAW_KEY: &str = "private-session-key-4306";
    let account = Account {
        members: vec![
            Some(FixtureUser {
                name: "Alice".into(),
                api_key: RAW_TOKEN.into(),
            }),
            None,
        ],
        sessions: BTreeMap::from([(RAW_KEY.into(), RAW_TOKEN.into())]),
    };
    let user: &dyn ToRedacted = &account;
    let roles = BypassJsonRedaction(&["reader", "writer"]);
    let fields = capture(|logger| {
        log::info!(logger: logger,
            user = user.log_redacted_json(), roles = roles.log_redacted_json();
            "signed in"
        );
    });
    let expected_key = if cfg!(feature = "mask-map-keys") {
        "[REDACTED-KEY-0]"
    } else {
        RAW_KEY
    };
    assert_eq!(
        fields,
        json!({
            "user": {
                "members": [{"name": "Alice", "api_key": "[REDACTED]"}, null],
                "sessions": {expected_key: "[REDACTED]"}
            },
            "roles": ["reader", "writer"]
        })
    );
    assert!(!fields.to_string().contains(RAW_TOKEN));
}

#[test]
fn borrowed_dual_output_can_be_logged_twice_after_one_production() {
    struct Counted(Cell<usize>);

    impl ToRedacted for Counted {
        fn to_redacted(&self) -> RedactedValue {
            self.0.set(self.0.get() + 1);
            GenericDualFixture {
                label: "login",
                secret: RAW_TOKEN.into(),
            }
            .to_redacted()
        }
    }

    let producer = Counted(Cell::new(0));
    let saved = producer.log_redacted_json();
    let text = SensitiveValue::<_, Secret>::from(RAW_TOKEN.to_owned());
    let fields = capture(|logger| {
        log::info!(logger: logger,
            first = &saved, second = &saved,
            text = text.log_redacted_json(), absent = None::<()>.log_redacted_json();
            "audit"
        );
    });
    let expected = json!({"label": "login", "secret": "[REDACTED]"});
    assert_eq!(
        fields,
        json!({
            "first": expected, "second": expected,
            "text": {"message": "[REDACTED]"}, "absent": null
        })
    );
    assert_eq!(producer.0.get(), 1);
    assert!(!fields.to_string().contains(RAW_TOKEN));
}

#[test]
fn failed_serializer_discards_partial_fields_and_private_error() {
    #[derive(Clone, SensitiveDual)]
    #[error("login {secret}")]
    struct FailingEvent {
        #[sensitive(Secret)]
        secret: String,
    }

    impl Serialize for FailingEvent {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut map = serializer.serialize_map(Some(1))?;
            map.serialize_entry("partial", &self.secret)?;
            Err(S::Error::custom(RAW_TOKEN))
        }
    }

    let event = FailingEvent {
        secret: RAW_TOKEN.into(),
    };
    let fields = capture(|logger| {
        log::info!(logger: logger, event = event.log_redacted_json(); "failed");
    });
    assert_eq!(fields, json!({"event": "[REDACTED]"}));
    assert!(!fields.to_string().contains(RAW_TOKEN));
}
