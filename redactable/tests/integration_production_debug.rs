//! Compares generated Debug in dependency libraries and consumer test builds.
//!
//! The same exact production representation must hold with or without the
//! `testing` feature. The fixture dependency is compiled without `cfg(test)`.

use redactable::{RedactableWithFormatter, ToRedacted};
use redactable_test_fixtures::{FixtureError, FixtureEvent, FixtureUser, GenericDualFixture};

#[test]
fn genuine_generic_dual_uses_production_redaction_paths() {
    let value = GenericDualFixture {
        label: String::from("event"),
        secret: String::from("generic-dual-production-canary-74b1"),
    };
    assert_eq!(value.redacted_display().to_string(), "event: [REDACTED]");
    assert_eq!(format!("{value:?}"), "event: [REDACTED]");
    // A dual producer carries both representations, and the `Debug` golden
    // shows exactly what is stored.
    assert_eq!(
        format!("{:?}", value.to_redacted()),
        "RedactedValue { text: \"event: [REDACTED]\", json: Object {\"label\": String(\"event\"), \"secret\": String(\"[REDACTED]\")} }"
    );
}

#[test]
fn sensitive_debug_redacts_in_production_builds() {
    let user = FixtureUser {
        name: "alice".into(),
        api_key: "sk-super-secret".into(),
    };
    assert_eq!(
        format!("{user:?}"),
        "FixtureUser { name: \"alice\", api_key: \"[REDACTED]\" }"
    );
}

#[test]
fn sensitive_display_debug_redacts_in_production_builds() {
    let error = FixtureError {
        user: "alice".into(),
        password: "hunter2".into(),
    };
    assert_eq!(
        format!("{error:?}"),
        "login failed for alice with [REDACTED]"
    );
}

#[test]
fn sensitive_enum_debug_uses_compact_variant_names_in_production_builds() {
    let event = FixtureEvent::Login {
        user: "alice".into(),
        token: "sk-super-secret".into(),
    };
    assert_eq!(
        format!("{event:?}"),
        "FixtureEvent::Login { user: \"alice\", token: \"[REDACTED]\" }"
    );
}

#[test]
fn redacted_display_is_unaffected_by_debug_mode() {
    let error = FixtureError {
        user: "alice".into(),
        password: "hunter2".into(),
    };
    assert_eq!(
        error.redacted_display().to_string(),
        "login failed for alice with [REDACTED]"
    );
}

mod consumer_test {
    use redactable::{Secret, Sensitive, SensitiveDisplay, SensitiveDual};
    use std::fmt::Display;

    #[derive(Clone, Sensitive, serde::Serialize)]
    pub struct FixtureUser {
        #[not_sensitive]
        pub name: String,
        #[sensitive(Secret)]
        pub api_key: String,
    }

    #[derive(SensitiveDisplay, serde::Serialize)]
    #[error("login failed for {user} with {password}")]
    pub struct FixtureError {
        #[not_sensitive]
        pub user: String,
        #[sensitive(Secret)]
        pub password: String,
    }

    #[derive(Clone, Sensitive, serde::Serialize)]
    pub enum FixtureEvent {
        Login {
            #[not_sensitive]
            user: String,
            #[sensitive(Secret)]
            token: String,
        },
    }

    #[derive(Clone, SensitiveDual, serde::Serialize)]
    #[error("{label}: {secret}")]
    pub struct GenericDualFixture<T: Display> {
        #[not_sensitive]
        pub label: T,
        #[sensitive(Secret)]
        pub secret: String,
    }
}

#[test]
fn consumer_test_types_match_the_production_goldens() {
    use self::consumer_test::{
        FixtureError as ConsumerFixtureError, FixtureEvent as ConsumerFixtureEvent,
        FixtureUser as ConsumerFixtureUser, GenericDualFixture as ConsumerGenericDualFixture,
    };

    let user = ConsumerFixtureUser {
        name: "alice".into(),
        api_key: "raw-secret".into(),
    };
    let error = ConsumerFixtureError {
        user: "alice".into(),
        password: "raw-secret".into(),
    };
    let event = ConsumerFixtureEvent::Login {
        user: "alice".into(),
        token: "raw-secret".into(),
    };
    let dual = ConsumerGenericDualFixture {
        label: "event",
        secret: "raw-secret".into(),
    };
    assert_eq!(
        format!("{user:?}"),
        "FixtureUser { name: \"alice\", api_key: \"[REDACTED]\" }"
    );
    assert_eq!(
        format!("{error:?}"),
        "login failed for alice with [REDACTED]"
    );
    assert_eq!(
        format!("{event:?}"),
        "FixtureEvent::Login { user: \"alice\", token: \"[REDACTED]\" }"
    );
    assert_eq!(format!("{dual:?}"), "event: [REDACTED]");
}

#[test]
fn policy_wrapper_and_opaque_output_keep_their_debug_bytes() {
    use redactable::{Pii, SensitiveValue};
    let wrapper = SensitiveValue::<String, Pii>::from("Alice".to_owned());
    assert_eq!(format!("{wrapper:?}"), "SensitiveValue(\"***ce\")");
    assert_eq!(
        format!("{:?}", wrapper.to_redacted()),
        "RedactedValue { text: \"***ce\" }"
    );

    {
        use redactable::{BypassJsonRedaction, ToRedacted};
        use serde_json::json;
        let selected = json!({"owner":"***ce"});
        let output = BypassJsonRedaction(&selected).to_redacted();
        assert_eq!(
            format!("{output:?}"),
            "RedactedValue { json: Object {\"owner\": String(\"***ce\")} }"
        );
    }
}
