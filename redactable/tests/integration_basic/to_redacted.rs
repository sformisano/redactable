use std::{cell::Cell, rc::Rc, sync::Arc};

use crate::log_redacted;
use redactable::{
    BypassDebugRedaction, BypassDisplayRedaction, BypassJsonRedaction, Redactable, RedactedValue,
    Secret, Sensitive, SensitiveDisplay, SensitiveDual, SensitiveValue, SensitiveWithPolicy,
    TextRedactionPolicy, ToRedacted,
};
use serde_json::{Value, json};

#[test]
fn accepts_escape_hatches() {
    #[derive(Clone, serde::Serialize)]
    struct ExternalId(String);

    impl SensitiveWithPolicy<Secret> for ExternalId {
        fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self {
            Self(policy.apply_to(&self.0))
        }

        fn redacted_string(&self, policy: &TextRedactionPolicy) -> String {
            policy.apply_to(&self.0)
        }
    }

    #[derive(Clone, Sensitive, serde::Serialize)]
    struct Event {
        id: SensitiveValue<ExternalId, Secret>,
        #[not_sensitive]
        status: String,
    }

    let event = Event {
        id: SensitiveValue::from(ExternalId("abc".into())),
        status: "ok".into(),
    };

    assert_eq!(log_redacted(&event.id).text(), "[REDACTED]");
    assert_eq!(
        log_redacted(&BypassDisplayRedaction(&event.status)).text(),
        "ok"
    );

    let debug_output = log_redacted(&BypassDebugRedaction(&event.status));
    assert_eq!(debug_output.text(), "\"ok\"");

    let structured = log_redacted(&event);
    assert_eq!(
        structured.json(),
        serde_json::json!({"id":"[REDACTED]","status":"ok"})
    );
}

#[test]
fn produces_the_redacted_json_of_a_cloned_value() {
    #[derive(Clone, Sensitive, serde::Serialize)]
    struct Event {
        #[sensitive(Secret)]
        token: String,
        #[not_sensitive]
        name: String,
    }

    let event = Event {
        token: "secret".into(),
        name: "alpha".into(),
    };

    let value = log_redacted(&event);
    assert_eq!(
        value.json(),
        serde_json::json!({"token":"[REDACTED]","name":"alpha"})
    );
    // The original is untouched, and its production `Debug` still redacts.
    assert_eq!(event.token, "secret");
    assert_eq!(
        format!("{event:?}"),
        "Event { token: \"[REDACTED]\", name: \"alpha\" }"
    );
}

#[test]
fn containers_of_derived_types_stay_certified_for_redaction() {
    #[derive(Clone, Sensitive, serde::Serialize)]
    struct Event {
        #[sensitive(Secret)]
        token: String,
    }

    let events = vec![Event {
        token: "secret".into(),
    }];
    assert_eq!(
        log_redacted(&BypassDebugRedaction(&events.clone().redact())).text(),
        "[Event { token: \"[REDACTED]\" }]"
    );

    let maybe_event = Some(Event {
        token: "secret".into(),
    });
    assert_eq!(
        log_redacted(&BypassDebugRedaction(&maybe_event.redact())).text(),
        "Some(Event { token: \"[REDACTED]\" })"
    );
}

const COMPOSITION_SECRET: &str = "producer-composition-private-account-7519";

fn assert_composed_output<T: ToRedacted>(mut producer: T, text: &str, json: Value) {
    let expected = log_redacted(&producer);
    assert_eq!(expected.text(), text);
    assert_eq!(expected.json(), json);
    assert!(!expected.text().contains(COMPOSITION_SECRET));
    assert!(!expected.json().to_string().contains(COMPOSITION_SECRET));

    // The generic boundary requires the wrapper's implementation, even when
    // method-call autoderef would also find the inner producer.
    assert_eq!(log_redacted(&Some(&producer)), expected);
    assert_eq!(log_redacted(&Some(Some(&producer))), expected);
    assert_eq!(log_redacted(&&producer), expected);
    assert_eq!(log_redacted(&&mut producer), expected);
    assert_eq!(log_redacted(&Box::new(&producer)), expected);
    assert_eq!(log_redacted(&Rc::new(&producer)), expected);
    assert_eq!(log_redacted(&Arc::new(&producer)), expected);

    let borrowed: &dyn ToRedacted = &producer;
    assert_eq!(log_redacted(&borrowed), expected);
    let boxed: Box<dyn ToRedacted + '_> = Box::new(&producer);
    assert_eq!(log_redacted(&boxed), expected);
    let shared: Rc<dyn ToRedacted + '_> = Rc::new(&producer);
    assert_eq!(log_redacted(&shared), expected);
    let atomic: Arc<dyn ToRedacted + '_> = Arc::new(&producer);
    assert_eq!(log_redacted(&atomic), expected);
    drop((boxed, shared, atomic));
    let borrowed_mut: &mut dyn ToRedacted = &mut producer;
    assert_eq!(log_redacted(&borrowed_mut), expected);
}

#[test]
fn composition_preserves_structured_text_and_dual_representations() {
    #[derive(Clone, Sensitive, serde::Serialize)]
    struct Structured {
        #[sensitive(Secret)]
        token: String,
    }

    /// account {token}
    #[derive(SensitiveDisplay)]
    struct Text {
        #[sensitive(Secret)]
        token: String,
    }

    /// account {token}
    #[derive(Clone, SensitiveDual, serde::Serialize)]
    struct Dual {
        #[sensitive(Secret)]
        token: String,
    }

    let structured = Structured {
        token: COMPOSITION_SECRET.into(),
    };
    assert_composed_output(
        &structured,
        r#"{"token":"[REDACTED]"}"#,
        json!({"token": "[REDACTED]"}),
    );
    assert_eq!(structured.token, COMPOSITION_SECRET);
    let text = Text {
        token: COMPOSITION_SECRET.into(),
    };
    assert_composed_output(
        &text,
        "account [REDACTED]",
        json!({"message": "account [REDACTED]"}),
    );
    assert_eq!(text.token, COMPOSITION_SECRET);
    let dual = Dual {
        token: COMPOSITION_SECRET.into(),
    };
    assert_composed_output(&dual, "account [REDACTED]", json!({"token": "[REDACTED]"}));
    assert_eq!(dual.token, COMPOSITION_SECRET);
}

struct BorrowedAccount<'a> {
    token: &'a str,
    calls: &'a Cell<usize>,
}

impl ToRedacted for BorrowedAccount<'_> {
    fn to_redacted(&self) -> RedactedValue {
        self.calls.set(self.calls.get() + 1);
        let selected = SensitiveValue::<_, Secret>::from(self.token.to_owned()).to_redacted();
        BypassJsonRedaction(&json!({"token": selected.text()})).to_redacted()
    }
}

#[test]
fn handwritten_borrowed_producers_compose_without_structural_or_formatting_bounds() {
    let token = String::from(COMPOSITION_SECRET);
    let calls = Cell::new(0);
    let account = Some(BorrowedAccount {
        token: &token,
        calls: &calls,
    });
    assert_composed_output(
        account,
        r#"{"token":"[REDACTED]"}"#,
        json!({"token": "[REDACTED]"}),
    );
    assert_eq!(token, COMPOSITION_SECRET);
}

#[test]
fn nested_forwarding_invokes_the_borrowed_producer_once() {
    let calls = Cell::new(0);
    let account = BorrowedAccount {
        token: COMPOSITION_SECRET,
        calls: &calls,
    };
    let wrapped = Some(Box::new(Rc::new(&account)));
    let output = log_redacted(&wrapped);
    assert_eq!(calls.get(), 1);
    assert_eq!(output.json(), json!({"token": "[REDACTED]"}));
    assert_eq!(output.text(), r#"{"token":"[REDACTED]"}"#);
    assert_eq!(calls.get(), 1);
    assert_eq!(account.token, COMPOSITION_SECRET);
}

#[test]
fn absent_unit_and_nested_null_producers_have_identical_json_null_output() {
    let expected = BypassJsonRedaction(&Value::Null).to_redacted();
    for output in [
        log_redacted(&None::<BorrowedAccount<'_>>),
        log_redacted(&()),
        log_redacted(&Some(())),
        log_redacted(&None::<Option<()>>),
        log_redacted(&Some(None::<()>)),
        log_redacted(&Some(Some(()))),
        log_redacted(&Some(BypassJsonRedaction(&Value::Null))),
    ] {
        assert_eq!(output, expected);
        assert_eq!(output.json(), Value::Null);
        assert_eq!(output.text(), "null");
    }
}
