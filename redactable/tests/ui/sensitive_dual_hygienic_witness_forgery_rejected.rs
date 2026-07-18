use redactable::Sensitive;

const CANARY: &str = "dual-forgery-secret-canary";

#[derive(Clone, Debug, Sensitive, serde::Serialize)]
#[sensitive(dual)]
struct ApiKey(#[sensitive(redactable::Token)] String);

impl redactable::RedactableWithFormatter for ApiKey {
    fn fmt_redacted(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("manual formatter")
    }
}

impl redactable::__private::SensitiveDisplayDeriveWitness for ApiKey {}

fn main() {
    let value = ApiKey(CANARY.to_owned());
    assert!(format!("{value:?}").contains(CANARY));
}
