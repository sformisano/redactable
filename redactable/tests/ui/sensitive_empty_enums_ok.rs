use redactable::{Redactable, RedactableWithFormatter, Sensitive, SensitiveDisplay};

#[derive(Clone, serde::Serialize, Sensitive)]
enum EmptySensitive {}

#[derive(serde::Serialize, SensitiveDisplay)]
enum EmptyDisplay {}

fn assert_sensitive<T: Redactable + core::fmt::Debug>() {}

fn assert_display<T: RedactableWithFormatter + core::fmt::Debug>() {}

fn main() {
    assert_sensitive::<EmptySensitive>();
    assert_display::<EmptyDisplay>();
}
