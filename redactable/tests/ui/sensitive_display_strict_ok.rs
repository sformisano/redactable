use redactable::{Secret, SensitiveDisplay};

#[derive(SensitiveDisplay)]
enum LoginError {
    #[error("user {user} secret {password}")]
    Invalid {
        #[not_sensitive]
        user: String,
        #[sensitive(Secret)]
        password: String,
    },
}

fn main() {}
