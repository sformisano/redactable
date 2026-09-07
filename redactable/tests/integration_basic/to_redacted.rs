use crate::log_redacted;
use redactable::{
    BypassDebugRedaction, BypassDisplayRedaction, Redactable, Secret, Sensitive, SensitiveValue,
    SensitiveWithPolicy, TextRedactionPolicy,
};

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

// `Redactable` forwards through std containers, so containers of derived types
// keep `.redact()`. They do not gain a producer: each derive generates its own
// `ToRedacted`, so logging a container declares the already-redacted value.
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
