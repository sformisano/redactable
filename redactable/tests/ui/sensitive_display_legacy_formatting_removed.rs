use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct Removed {
    #[sensitive(redactable::Secret)]
    #[redactable(legacy_formatting)]
    value: Option<String>,
}

fn main() {}
