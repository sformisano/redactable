use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct UnknownOption {
    #[sensitive(redactable::Secret)]
    #[redactable(legacy)]
    value: Option<String>,
}

fn main() {}
