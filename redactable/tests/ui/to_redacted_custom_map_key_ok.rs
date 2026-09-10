//! Ordinary custom and string map keys stay usable, and a borrow-sensitive key
//! remains valid for redaction, which never clones or inspects it.

use std::{cell::RefCell, collections::BTreeMap};

use redactable::{Redactable, Secret, Sensitive, ToRedacted};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
struct CustomKey(String);

#[derive(Clone, Sensitive, serde::Serialize)]
struct Record {
    #[sensitive(Secret)]
    secret: u64,
}

#[derive(Clone, Sensitive, serde::Serialize)]
struct CustomKeyed {
    records: BTreeMap<CustomKey, Record>,
}

#[derive(Clone, Sensitive, serde::Serialize)]
struct StringKeyed {
    records: BTreeMap<String, Record>,
}

fn main() {
    let records = BTreeMap::from([(CustomKey(String::from("key")), Record { secret: 42 })]);
    let _ = CustomKeyed { records }.to_redacted();

    let records = BTreeMap::from([(String::from("key"), Record { secret: 42 })]);
    let _ = StringKeyed { records }.to_redacted();

    let borrow_sensitive =
        BTreeMap::from([(RefCell::new(String::from("key")), Record { secret: 42 })]);
    let _ = borrow_sensitive.redact();
}
