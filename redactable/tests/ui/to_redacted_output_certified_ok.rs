use std::hash::Hash;

use redactable::{
    NotSensitiveDebug, NotSensitiveDebugExt, NotSensitiveDisplay, NotSensitiveDisplayExt,
    Redactable, RedactedOutputExt, Secret, Sensitive, SensitiveDisplay, SensitiveValue,
    ToRedactedOutput, UncheckedRedactedSummary,
};
use serde::Serialize;

fn assert_redacted_output<T: ToRedactedOutput>(value: &T) {
    let _ = value.to_redacted_output();
}

fn assert_common_traits<T: Clone + Copy + Default + Eq + Ord + Hash>() {}

#[derive(Clone, Sensitive, Serialize)]
struct Account {
    #[sensitive(Secret)]
    token: String,
    #[not_sensitive]
    name: String,
}

#[derive(SensitiveDisplay)]
enum LoginError {
    #[error("login failed for {user} {password}")]
    Invalid {
        #[not_sensitive]
        user: String,
        #[sensitive(Secret)]
        password: String,
    },
}

fn main() {
    let account = Account {
        token: String::from("secret"),
        name: String::from("alice"),
    };
    let err = LoginError::Invalid {
        user: String::from("alice"),
        password: String::from("hunter2"),
    };
    let token = SensitiveValue::<String, Secret>::from(String::from("secret"));
    let public = String::from("ok");
    let output =
        UncheckedRedactedSummary::new(String::from("already redacted")).to_redacted_output();

    assert_redacted_output(&account.redacted_output());
    assert_redacted_output(&err);
    assert_redacted_output(&token);
    assert_redacted_output(&public.not_sensitive_display());
    assert_redacted_output(&public.not_sensitive_debug());
    assert_redacted_output(&NotSensitiveDisplay(String::from("owned")));
    assert_redacted_output(&NotSensitiveDebug(String::from("owned")));
    assert_redacted_output(&output);
    assert_common_traits::<NotSensitiveDisplay<u64>>();
    assert_common_traits::<NotSensitiveDebug<u64>>();

    let _ = account.redact();
}
