use std::cell::RefCell;

use redactable::{NotSensitive, RedactedOutputExt, ToRedactedOutput};

type CellAlias<T> = RefCell<T>;

#[derive(Clone, Debug, NotSensitive, serde::Serialize)]
struct Direct(CellAlias<String>);

#[derive(Clone, Debug, NotSensitive, serde::Serialize)]
struct Generic<T>(T);

fn main() {
    let direct = Direct(RefCell::new(String::new()));
    let _ = direct.redacted_output().to_redacted_output();

    let generic = Generic(RefCell::new(String::new()));
    let _ = generic.redacted_output().to_redacted_output();
}
