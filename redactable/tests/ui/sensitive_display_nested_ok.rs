use redactable::{Secret, SensitiveDisplay};

#[derive(SensitiveDisplay)]
enum InnerError {
    #[error("db password {password}")]
    BadPassword {
        #[sensitive(Secret)]
        password: String,
    },
}

#[derive(SensitiveDisplay)]
enum OuterError {
    #[error("request failed: {source}")]
    RequestFailed { source: InnerError },
}

fn main() {
    let err = OuterError::RequestFailed {
        source: InnerError::BadPassword {
            password: "secret".into(),
        },
    };

    let _ = redactable::RedactableDisplay::redacted_display(&err);
}
