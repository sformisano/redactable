use std::hash::Hash;

use redactable::{
    BypassDebugRedaction, BypassDisplayRedaction, BypassTextRedaction, Redactable, Secret,
    Sensitive, SensitiveDisplay, SensitiveValue, ToRedacted,
};
use serde::Serialize;

fn assert_redacted_output<T: ToRedacted>(value: &T) {
    let _ = value.to_redacted();
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
        BypassTextRedaction(String::from("already redacted")).to_redacted();

    assert_redacted_output(&account);
    assert_redacted_output(&err);
    assert_redacted_output(&token);
    assert_redacted_output(&BypassDisplayRedaction(&public));
    assert_redacted_output(&BypassDebugRedaction(&public));
    assert_redacted_output(&BypassDisplayRedaction(String::from("owned")));
    assert_redacted_output(&BypassDebugRedaction(String::from("owned")));
    assert_redacted_output(&output);
    assert_common_traits::<BypassDisplayRedaction<u64>>();
    assert_common_traits::<BypassDebugRedaction<u64>>();

    let _ = account.redact();
}
