use redactable::Sensitive;

#[derive(Clone, serde::Serialize, Sensitive)]
struct StructuralOnly {
    #[sensitive(redactable::Secret)]
    #[redactable(legacy_formatting)]
    value: Option<String>,
}

fn main() {}
