use super::*;

#[test]
fn applies_full_redaction_by_default() {
    let sensitive = String::from("my_secret_password");
    let policy = TextRedactionPolicy::default_full();
    let redacted = policy.apply_to(&sensitive);
    assert_eq!(redacted, "[REDACTED]");
}
