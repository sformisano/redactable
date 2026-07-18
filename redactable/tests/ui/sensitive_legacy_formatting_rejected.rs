use redactable::Sensitive;

#[derive(Sensitive)]
struct StructuralOnly {
    #[sensitive(redactable::Secret)]
    #[redactable(legacy_formatting)]
    value: Option<String>,
}

fn main() {}
