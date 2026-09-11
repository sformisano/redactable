//! Integration tests for the tracing module.
//!
//! These tests install a small subscriber and assert the actual field values
//! delivered through tracing's visitor API.

#![cfg(feature = "tracing")]
#![allow(unexpected_cfgs)]

use std::{
    fmt::Debug,
    sync::{Arc, Mutex, MutexGuard},
};

use redactable::{
    RedactableWithFormatter, Secret, SensitiveValue, ToRedacted,
    tracing::{TracingRedactedDebugExt, TracingRedactedExt},
};
use redactable_test_fixtures::{AuthEvent, FixtureError, FixtureUser, GenericDualFixture};
use tracing::{
    Event, Id, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Record},
    subscriber::with_default,
};
#[cfg(all(feature = "tracing-valuable", tracing_unstable))]
use valuable::{NamedValues, Valuable as _, Value as ValuableValue, Visit as ValuableVisit};

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordedField {
    name: String,
    value: RecordedValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RecordedValue {
    Debug(String),
    Str(String),
    #[cfg(all(feature = "tracing-valuable", tracing_unstable))]
    Valuable(Vec<(String, String)>),
}

#[derive(Clone, Default)]
struct CapturingSubscriber {
    fields: Arc<Mutex<Vec<RecordedField>>>,
}

impl CapturingSubscriber {
    fn lock_fields(&self) -> MutexGuard<'_, Vec<RecordedField>> {
        self.fields
            .lock()
            .expect("capturing subscriber fields lock should not be poisoned")
    }

    fn captured_fields(&self) -> Vec<RecordedField> {
        self.lock_fields().clone()
    }
}

struct CapturingVisitor<'a> {
    fields: &'a mut Vec<RecordedField>,
}

impl CapturingVisitor<'_> {
    fn push(&mut self, field: &Field, value: RecordedValue) {
        self.fields.push(RecordedField {
            name: field.name().to_owned(),
            value,
        });
    }
}

impl Visit for CapturingVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.push(field, RecordedValue::Debug(format!("{value:?}")));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, RecordedValue::Str(value.to_owned()));
    }

    #[cfg(all(feature = "tracing-valuable", tracing_unstable))]
    fn record_value(&mut self, field: &Field, value: ValuableValue<'_>) {
        let mut capture = ValuableCapture::default();
        value.visit(&mut capture);
        self.push(field, RecordedValue::Valuable(capture.fields));
    }
}

impl Subscriber for CapturingSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, span: &Attributes<'_>) -> Id {
        let mut fields = self.lock_fields();
        span.record(&mut CapturingVisitor {
            fields: &mut fields,
        });
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, values: &Record<'_>) {
        let mut fields = self.lock_fields();
        values.record(&mut CapturingVisitor {
            fields: &mut fields,
        });
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut fields = self.lock_fields();
        event.record(&mut CapturingVisitor {
            fields: &mut fields,
        });
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

#[cfg(all(feature = "tracing-valuable", tracing_unstable))]
#[derive(Default)]
struct ValuableCapture {
    fields: Vec<(String, String)>,
}

#[cfg(all(feature = "tracing-valuable", tracing_unstable))]
impl ValuableVisit for ValuableCapture {
    fn visit_value(&mut self, value: ValuableValue<'_>) {
        if let Some(value) = value.as_structable() {
            value.visit(self);
        }
    }

    fn visit_named_fields(&mut self, named_values: &NamedValues<'_>) {
        for (field, value) in named_values.iter() {
            self.fields
                .push((field.name().to_owned(), valuable_value_to_string(*value)));
        }
    }
}

#[cfg(all(feature = "tracing-valuable", tracing_unstable))]
fn valuable_value_to_string(value: ValuableValue<'_>) -> String {
    value
        .as_str()
        .map_or_else(|| format!("{value:?}"), ToOwned::to_owned)
}

fn capture_fields(record: impl FnOnce()) -> Vec<RecordedField> {
    let subscriber = CapturingSubscriber::default();
    let handle = subscriber.clone();
    with_default(subscriber, record);
    handle.captured_fields()
}

fn field_named<'a>(fields: &'a [RecordedField], name: &str) -> &'a RecordedField {
    fields
        .iter()
        .find(|field| field.name == name)
        .expect("expected tracing field to be recorded")
}

fn debug_text<'a>(field: &'a RecordedField, name: &str) -> &'a str {
    let RecordedValue::Debug(output) = &field.value else {
        panic!("{name} field should be recorded through Debug");
    };
    output
}

#[test]
fn structural_debug_helper_records_redacted_debug_field() {
    let user = FixtureUser {
        name: "alice".to_owned(),
        api_key: "sk-super-secret".to_owned(),
    };

    let fields = capture_fields(|| tracing::info!(user = user.tracing_redacted_debug()));
    let user = field_named(&fields, "user");
    let output = debug_text(user, "user");

    assert!(
        output.contains("alice"),
        "non-sensitive field should remain visible, got: {output}"
    );
    assert!(
        output.contains("[REDACTED]"),
        "sensitive field should be redacted, got: {output}"
    );
    assert!(
        !output.contains("sk-super-secret"),
        "raw sensitive field must not reach tracing, got: {output}"
    );
}

#[test]
fn production_auth_event_tracing_matches_documentation() {
    const API_KEY: &str = "sk-secret-key-12345";
    const EMAIL: &str = "alice@example.com";
    let event = AuthEvent {
        api_key: API_KEY.to_owned(),
        user_email: EMAIL.to_owned(),
        action: "login".to_owned(),
    };

    let fields = capture_fields(|| tracing::info!(event = event.tracing_redacted_debug()));
    let output = debug_text(field_named(&fields, "event"), "event");
    let expected =
        "AuthEvent { api_key: \"[REDACTED]\", user_email: \"[REDACTED]\", action: \"login\" }";

    assert_eq!(output, expected);
    assert!(!output.contains(API_KEY));
    assert!(!output.contains(EMAIL));
}

#[test]
fn genuine_generic_dual_tracing_omits_canary() {
    const CANARY: &str = "generic-dual-tracing-canary-1e39";
    let value = GenericDualFixture {
        label: String::from("event"),
        secret: String::from(CANARY),
    };

    let fields = capture_fields(|| tracing::info!(value = value.tracing_redacted()));
    let output = debug_text(field_named(&fields, "value"), "value");
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains(CANARY));
}

#[test]
fn display_helper_records_redacted_display_field() {
    let token = SensitiveValue::<String, Secret>::from("hunter2".to_owned());
    let error = FixtureError {
        user: "alice".to_owned(),
        password: "raw-password".to_owned(),
    };

    let fields = capture_fields(|| {
        tracing::info!(
            token = token.tracing_redacted(),
            login_error = error.tracing_redacted()
        );
    });
    let token = field_named(&fields, "token");
    let token_output = debug_text(token, "token");
    let error = field_named(&fields, "login_error");
    let error_output = debug_text(error, "login_error");

    assert_eq!(token_output, "[REDACTED]");
    assert_eq!(
        error_output, "login failed for alice with [REDACTED]",
        "SensitiveDisplay tracing output must redact template fields"
    );
    assert!(
        !error_output.contains("raw-password"),
        "raw display secret must not reach tracing, got: {error_output}"
    );
}

#[test]
fn unsized_producer_tracing_text_matches_concrete_output() {
    let token = SensitiveValue::<String, Secret>::from("unsized-tracing-canary".to_owned());
    let producer: &dyn ToRedacted = &token;

    let fields = capture_fields(|| {
        tracing::info!(
            concrete = token.tracing_redacted(),
            dynamic = producer.tracing_redacted(),
        );
    });
    let concrete = debug_text(field_named(&fields, "concrete"), "concrete");
    let dynamic = debug_text(field_named(&fields, "dynamic"), "dynamic");

    assert_eq!(concrete, "[REDACTED]");
    assert_eq!(dynamic, concrete);
}

#[cfg(feature = "tracing-valuable")]
#[test]
fn valuable_error_projection_forwards_caller_mutation() {
    use std::{
        cell::RefCell,
        error::Error,
        fmt::{Display, Formatter, Result as FmtResult},
    };

    use redactable::{Sensitive, tracing::IntoTracingRedactedValuableExt};
    use valuable::{Valuable, Value as ValuableValue, Visit as ValuableVisit};

    #[derive(Clone, serde::Serialize, Sensitive)]
    struct Event {
        #[sensitive(Secret)]
        secret: RefCell<String>,
    }

    impl Display for Event {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
            formatter.write_str(&self.secret.borrow())
        }
    }

    impl Error for Event {}

    impl Valuable for Event {
        fn as_value(&self) -> ValuableValue<'_> {
            ValuableValue::Error(self)
        }

        fn visit(&self, visit: &mut dyn ValuableVisit) {
            visit.visit_value(self.as_value());
        }
    }

    let wrapped = Event {
        secret: RefCell::new("original-secret".to_owned()),
    }
    .into_tracing_redacted_valuable();
    let projection = wrapped.as_value();
    let error = projection
        .as_error()
        .expect("valuable projection should expose the inner error");
    assert_eq!(error.to_string(), "[REDACTED]");

    error
        .downcast_ref::<Event>()
        .expect("borrowed error should retain its concrete type")
        .secret
        .replace("caller-update".to_owned());

    let later_projection = wrapped.as_value();
    let later = later_projection
        .as_error()
        .expect("later projection should still expose the inner error");
    assert_eq!(later.to_string(), "caller-update");
}

#[test]
fn redacted_display_works_with_tracing_display_field() {
    let error = FixtureError {
        user: "alice".to_owned(),
        password: "raw-password".to_owned(),
    };

    let fields = capture_fields(|| tracing::info!(login_error = %error.redacted_display()));
    let error = field_named(&fields, "login_error");
    let output = debug_text(error, "login_error");

    assert_eq!(output, "login failed for alice with [REDACTED]");
    assert!(
        !output.contains("raw-password"),
        "raw display secret must not reach tracing, got: {output}"
    );
}

#[cfg(all(feature = "tracing-valuable", tracing_unstable))]
#[test]
fn valuable_structured_output_records_redacted_fields() {
    use redactable::{Sensitive, tracing::TracingValuableExt};

    #[derive(serde::Serialize, Clone, Sensitive, valuable::Valuable)]
    struct ValuableUser {
        #[not_sensitive]
        username: String,
        #[sensitive(Secret)]
        password: String,
    }

    let user = ValuableUser {
        username: "alice".to_owned(),
        password: "hunter2".to_owned(),
    };

    let fields = capture_fields(|| {
        let redacted = user.tracing_redacted_valuable();
        tracing::info!(user = tracing::field::valuable(&redacted));
    });
    let user = field_named(&fields, "user");
    let RecordedValue::Valuable(values) = &user.value else {
        panic!("user field should be recorded through valuable");
    };

    assert_eq!(
        values,
        &vec![
            ("username".to_owned(), "alice".to_owned()),
            ("password".to_owned(), "[REDACTED]".to_owned()),
        ]
    );
}

// Closes review issue #6: the consuming Valuable adapter was only ever asserted
// through `TracingRedactedValue::into_inner()`, which inspects the redacted value without
// ever driving it through a real visitor. That leaves the actual logging path --
// what a subscriber records -- untested. This is the consuming counterpart to
// `valuable_structured_output_records_redacted_fields`, using the same real
// subscriber harness, with a canary that must never reach the visitor.
#[cfg(all(feature = "tracing-valuable", tracing_unstable))]
#[test]
fn valuable_structured_output_records_redacted_fields_from_consuming_adapter() {
    use redactable::{Sensitive, tracing::IntoTracingRedactedValuableExt};

    #[derive(serde::Serialize, Clone, Sensitive, valuable::Valuable)]
    struct ConsumedValuableUser {
        #[not_sensitive]
        username: String,
        #[sensitive(Secret)]
        password: String,
    }

    let user = ConsumedValuableUser {
        username: "alice".to_owned(),
        password: "consuming-valuable-canary".to_owned(),
    };

    let fields = capture_fields(|| {
        // Consuming adapter: redacts the owned value, no clone of the original.
        let redacted = user.into_tracing_redacted_valuable();
        tracing::info!(user = tracing::field::valuable(&redacted));
    });
    let user = field_named(&fields, "user");
    let RecordedValue::Valuable(values) = &user.value else {
        panic!("user field should be recorded through valuable");
    };

    assert_eq!(
        values,
        &vec![
            ("username".to_owned(), "alice".to_owned()),
            ("password".to_owned(), "[REDACTED]".to_owned()),
        ]
    );
    // The canary must not survive anywhere the subscriber can see it.
    assert!(
        !format!("{values:?}").contains("consuming-valuable-canary"),
        "raw secret reached the valuable visitor: {values:?}"
    );
}
