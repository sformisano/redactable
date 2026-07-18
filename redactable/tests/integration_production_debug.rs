//! Asserts derive-generated `Debug` output on types compiled outside test builds.
//!
//! The fixture types live in `redactable-test-fixtures`, which is compiled as a
//! dependency (`cfg!(test)` is false there). Their `Debug` impls therefore take
//! the production branch: redacted output by default, raw output only when
//! `redactable`'s own `testing` feature is enabled. Types defined inside this
//! test file could never cover that branch because the whole test crate is
//! compiled with `cfg(test)`.

use redactable::{RedactableWithFormatter, ToRedactedOutput};
use redactable_test_fixtures::{FixtureError, FixtureEvent, FixtureUser, GenericDualFixture};

/// True when `redactable` itself was built with the `testing` feature, which
/// flips derived `Debug` to raw output by design.
const TESTING_MODE: bool = cfg!(feature = "testing");

#[test]
fn genuine_generic_dual_uses_production_redaction_paths() {
    const CANARY: &str = "generic-dual-production-canary-74b1";
    let value = GenericDualFixture {
        label: String::from("event"),
        secret: String::from(CANARY),
    };

    let display = value.redacted_display().to_string();
    let output = format!("{:?}", value.to_redacted_output());
    assert!(display.contains("[REDACTED]"));
    assert!(!display.contains(CANARY));
    assert!(!output.contains(CANARY));

    let debug = format!("{value:?}");
    if !TESTING_MODE {
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(CANARY));
    }
}

#[test]
fn sensitive_debug_redacts_in_production_builds() {
    let user = FixtureUser {
        name: "alice".to_string(),
        api_key: "sk-super-secret".to_string(),
    };
    let output = format!("{user:?}");

    if TESTING_MODE {
        assert!(
            output.contains("sk-super-secret"),
            "testing feature should reveal raw Debug output, got: {output}"
        );
    } else {
        assert!(
            !output.contains("sk-super-secret"),
            "production Debug must not leak the raw value, got: {output}"
        );
        assert!(
            output.contains("[REDACTED]"),
            "production Debug should use the redacted placeholder, got: {output}"
        );
        assert!(
            output.contains("alice"),
            "non-sensitive fields stay visible in production Debug, got: {output}"
        );
    }
}

#[test]
fn sensitive_display_debug_redacts_in_production_builds() {
    let err = FixtureError {
        user: "alice".to_string(),
        password: "hunter2".to_string(),
    };
    let output = format!("{err:?}");

    if TESTING_MODE {
        assert!(
            output.contains("hunter2"),
            "testing feature should reveal raw Debug output, got: {output}"
        );
    } else {
        assert!(
            !output.contains("hunter2"),
            "production Debug must not leak the raw value, got: {output}"
        );
        assert!(
            output.contains("[REDACTED]"),
            "production Debug formats through the redacted template, got: {output}"
        );
        assert!(
            output.contains("alice"),
            "non-sensitive template fields stay visible, got: {output}"
        );
    }
}

#[test]
fn sensitive_enum_debug_uses_compact_variant_names_in_production_builds() {
    let event = FixtureEvent::Login {
        user: "alice".to_string(),
        token: "sk-super-secret".to_string(),
    };
    let output = format!("{event:?}");

    assert!(
        output.contains("FixtureEvent::Login"),
        "enum Debug should use Rust-style variant names, got: {output}"
    );
    assert!(
        !output.contains("FixtureEvent :: Login"),
        "enum Debug should not include stringify spacing, got: {output}"
    );
    if !TESTING_MODE {
        assert!(
            !output.contains("sk-super-secret"),
            "production Debug must not leak the raw value, got: {output}"
        );
        assert!(
            output.contains("[REDACTED]"),
            "production Debug should redact sensitive enum fields, got: {output}"
        );
    }
}

#[test]
fn redacted_display_is_unaffected_by_debug_mode() {
    let err = FixtureError {
        user: "alice".to_string(),
        password: "hunter2".to_string(),
    };
    // `.redacted_display()` always redacts, in every build mode.
    use redactable::RedactableWithFormatter as _;
    let output = err.redacted_display().to_string();
    assert_eq!(output, "login failed for alice with [REDACTED]");
}
