//! Values-only map redaction never clones or inspects a key, so a
//! borrow-sensitive key stays usable on every route.

use std::{cell::RefCell, collections::BTreeMap};

use redactable::{Redactable, Secret, Sensitive, ToRedacted};

#[derive(Clone, Sensitive, serde::Serialize)]
struct Record {
    #[sensitive(Secret)]
    secret: u64,
}

#[derive(Clone, Sensitive, serde::Serialize)]
struct Holder {
    records: BTreeMap<RefCell<String>, Record>,
}

fn main() {
    let records = BTreeMap::from([(RefCell::new(String::from("key")), Record { secret: 42 })]);

    let _ = records.clone().redact();
    let _ = Holder { records }.to_redacted();
}
