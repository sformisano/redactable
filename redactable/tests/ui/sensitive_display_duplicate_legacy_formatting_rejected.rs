use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct DuplicateOption {
    #[sensitive(redactable::Secret)]
    #[redactable(legacy_formatting, legacy_formatting)]
    value: Option<String>,
}

fn main() {}
