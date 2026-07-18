use std::{cell::RefCell, collections::BTreeMap};

use redactable::{RedactedOutputExt, Secret, Sensitive, ToRedactedOutput};

#[derive(Clone, Sensitive, serde::Serialize)]
struct Record {
    #[sensitive(Secret)]
    secret: u64,
}

fn main() {
    let records = BTreeMap::from([(RefCell::new(String::from("key")), Record { secret: 42 })]);

    let _ = records.redacted_output().to_redacted_output();
}
