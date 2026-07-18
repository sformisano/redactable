use super::*;

#[test]
fn accepts_escape_hatches() {
    #[derive(Clone)]
    #[cfg_attr(feature = "json", derive(serde::Serialize))]
    struct ExternalId(String);

    impl SensitiveWithPolicy<Secret> for ExternalId {
        fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self {
            Self(policy.apply_to(&self.0))
        }

        fn redacted_string(&self, policy: &TextRedactionPolicy) -> String {
            policy.apply_to(&self.0)
        }
    }

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "json", derive(serde::Serialize))]
    struct Event {
        id: SensitiveValue<ExternalId, Secret>,
        status: String,
    }

    let event = Event {
        id: SensitiveValue::from(ExternalId("abc".into())),
        status: "ok".into(),
    };

    assert_eq!(
        log_redacted(&event.id),
        RedactedOutput::Text("[REDACTED]".to_string())
    );
    assert_eq!(
        log_redacted(&event.status.not_sensitive_display()),
        RedactedOutput::Text("ok".to_string())
    );

    let debug_output = log_redacted(&event.status.not_sensitive_debug());
    assert_eq!(debug_output, RedactedOutput::Text("\"ok\"".to_string()));

    let structured = log_redacted(&event.redacted_output());
    assert_eq!(
        structured,
        RedactedOutput::Text(
            "Event { id: SensitiveValue(\"[REDACTED]\"), status: \"ok\" }".to_string()
        )
    );
}

#[test]
fn produces_debug_formatted_output() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Event {
        #[sensitive(Secret)]
        token: String,
        name: String,
    }

    let event = Event {
        token: "secret".into(),
        name: "alpha".into(),
    };

    let redacted_output = log_redacted(&event.redacted_output());
    assert_eq!(
        redacted_output,
        RedactedOutput::Text("Event { token: \"[REDACTED]\", name: \"alpha\" }".to_string())
    );
}

// Redactable forwards through std containers, so containers of
// derived types keep access to the certified extension methods even though
// raw passthrough leaves (String, scalars) do not.
#[test]
fn containers_of_derived_types_stay_certified() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Event {
        #[sensitive(Secret)]
        token: String,
    }

    let events = vec![Event {
        token: "secret".into(),
    }];
    assert_eq!(
        log_redacted(&events.redacted_output()),
        RedactedOutput::Text("[Event { token: \"[REDACTED]\" }]".to_string())
    );

    let maybe_event = Some(Event {
        token: "secret".into(),
    });
    assert_eq!(
        log_redacted(&maybe_event.redacted_output()),
        RedactedOutput::Text("Some(Event { token: \"[REDACTED]\" })".to_string())
    );
}
