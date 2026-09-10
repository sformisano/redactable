// Test: NotSensitive rejects #[not_sensitive] attributes on fields

use redactable::NotSensitive;

#[derive(serde::Serialize, Debug, NotSensitive)]
struct PublicData {
    #[not_sensitive]
    name: String,
}

fn main() {}
