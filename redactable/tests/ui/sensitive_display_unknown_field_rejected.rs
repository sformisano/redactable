use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
#[error("login failed for {username}")]
struct LoginError {
    #[sensitive(redactable::Secret)]
    password: String,
}

fn main() {}
