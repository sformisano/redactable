// Test: SensitiveDisplay can be used inside #[derive(Sensitive)] container
// This works because SensitiveDisplay now provides RedactableWithMapper.

use redactable::{Redactable, Secret, Sensitive, SensitiveDisplay, Token};

/// {0}
#[derive(Clone, SensitiveDisplay)]
#[cfg_attr(feature = "slog", derive(serde::Serialize))]
#[sensitive(skip_debug)]
struct Email(#[sensitive(Token)] String);

impl std::fmt::Debug for Email {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Email({})", self.0)
    }
}

// This container has a field using SensitiveDisplay type.
// Previously this would fail because SensitiveDisplay didn't generate RedactableWithMapper.
#[derive(Clone, Sensitive)]
#[cfg_attr(feature = "slog", derive(serde::Serialize))]
struct UserProfile {
    email: Email,
    #[sensitive(Secret)]
    api_key: String,
}

fn main() {
    let profile = UserProfile {
        email: Email("alice@example.com".into()),
        api_key: "sk_live_secret123".into(),
    };

    // Verify the container can be redacted (requires Email: RedactableWithMapper)
    let redacted = profile.redact();

    // Email's inner Token-annotated string is redacted by the real RedactableWithMapper
    assert_eq!(redacted.email.0, "*************.com");
    // Sensitive field is redacted
    assert_eq!(redacted.api_key, "[REDACTED]");

    // Display is still redacted via RedactableWithFormatter
    let display = format!(
        "{}",
        redactable::RedactableWithFormatter::redacted_display(&redacted.email)
    );
    assert_eq!(display, "*************.com");
}
