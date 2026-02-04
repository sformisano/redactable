use redactable::{Default as RedactableDefault, SensitiveDisplay};

#[derive(SensitiveDisplay)]
enum LoginError {
    #[error("user {user} secret {password}")]
    Invalid {
        #[not_sensitive]
        user: String,
        #[sensitive(RedactableDefault)]
        password: String,
    },
}

fn main() {}
