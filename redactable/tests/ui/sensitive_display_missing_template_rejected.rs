use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
struct LoginError {
    #[sensitive(redactable::Secret)]
    password: String,
}

fn main() {}
