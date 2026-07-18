use std::cell::RefCell;

use redactable::{RedactedOutputExt, Sensitive, ToRedactedOutput};

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

fn main() {
    let direct = Direct {
        value: RefCell::new(String::new()),
    };
    let _ = direct.redacted_output().to_redacted_output();

    let generic = Generic {
        value: RefCell::new(String::new()),
    };
    let _ = generic.redacted_output().to_redacted_output();
}
