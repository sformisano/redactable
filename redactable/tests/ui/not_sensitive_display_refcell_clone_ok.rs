use std::{
    cell::RefCell,
    fmt::{Display, Formatter, Result as FmtResult},
};

use redactable::{NotSensitiveDisplay, ToRedacted};

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
    let _ = direct.to_redacted();

    let generic = Generic(RefCell::new(String::new()));
    let _ = generic.to_redacted();
}
