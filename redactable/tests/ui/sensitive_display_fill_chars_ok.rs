use redactable::{RedactableWithFormatter, Secret, SensitiveDisplay};

#[derive(SensitiveDisplay)]
#[error("token {token:*>12} mirror {token:$<12}")]
struct FillChars {
    #[sensitive(Secret)]
    token: String,
}

fn main() {
    let value = FillChars {
        token: "secret".to_string(),
    };
    assert_eq!(
        value.redacted_display().to_string(),
        "token **[REDACTED] mirror [REDACTED]$$"
    );
}
