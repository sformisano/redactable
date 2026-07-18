use std::{cell::RefCell, collections::BTreeMap};

use redactable::{Redactable, RedactedOutputExt, Secret, Sensitive, ToRedactedOutput};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CustomKey(String);

#[derive(Clone, Sensitive, serde::Serialize)]
struct Record {
    #[sensitive(Secret)]
    secret: u64,
}

fn main() {
    let records = BTreeMap::from([(
        CustomKey(String::from("key")),
        Record { secret: 42 },
    )]);

    let _ = records.redacted_output().to_redacted_output();

    let string_keyed = BTreeMap::from([(String::from("key"), Record { secret: 42 })]);
    let _ = string_keyed.redacted_output().to_redacted_output();

    // Borrow-sensitive keys remain valid for consuming redaction, which never
    // clones or inspects the key.
    let borrow_sensitive = BTreeMap::from([(
        RefCell::new(String::from("key")),
        Record { secret: 42 },
    )]);
    let _ = borrow_sensitive.redact();
}
