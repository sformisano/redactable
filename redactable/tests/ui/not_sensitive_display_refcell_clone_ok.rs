use std::{
    cell::RefCell,
    fmt::{Display, Formatter, Result as FmtResult},
};

use redactable::{NotSensitiveDisplay, RedactedJsonExt, ToRedactedOutput};

type CellAlias<T> = RefCell<T>;

#[derive(Clone, NotSensitiveDisplay, serde::Serialize)]
struct Direct(CellAlias<String>);

impl Display for Direct {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str("direct")
    }
}

#[derive(Clone, NotSensitiveDisplay, serde::Serialize)]
struct Generic<T>(T);

impl<T> Display for Generic<T> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str("generic")
    }
}

fn main() {
    let direct = Direct(RefCell::new(String::new()));
    let _ = direct.redacted_json().to_redacted_output();

    let generic = Generic(RefCell::new(String::new()));
    let _ = generic.redacted_json().to_redacted_output();
}
