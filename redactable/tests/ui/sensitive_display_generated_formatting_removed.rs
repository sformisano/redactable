use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct Removed {
    #[sensitive(redactable::Secret)]
    #[redactable(generated_formatting)]
    value: Vec<String>,
}

fn main() {}
