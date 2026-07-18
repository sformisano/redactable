use std::cell::RefCell;

use redactable::Sensitive;

type CellAlias<T> = RefCell<T>;

#[derive(Clone, Sensitive, serde::Serialize)]
struct Direct {
    #[not_sensitive]
    value: CellAlias<String>,
}

#[derive(Clone, Sensitive, serde::Serialize)]
struct Generic<T> {
    #[not_sensitive]
    value: T,
}

fn assert_slog<T: redactable::__private::slog::Value>() {}

fn main() {
    assert_slog::<Generic<RefCell<String>>>();
}
