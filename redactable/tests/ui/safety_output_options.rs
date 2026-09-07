use redactable::{NotSensitive, NotSensitiveDisplay, Sensitive, SensitiveDisplay, SensitiveDual};
#[derive(Sensitive)]
#[redactable()]
struct Empty;
#[derive(Sensitive)]
#[redactable(output = text)]
struct WrongFormat;
#[derive(Sensitive)]
#[redactable(output = "json")]
struct Literal;
#[derive(Sensitive)]
#[redactable(output = json, output = json)]
struct Duplicate;
#[derive(Sensitive)]
#[redactable(output = json)]
#[redactable(output = json)]
struct Repeated;
#[derive(SensitiveDisplay)]
#[redactable(output = json)]
#[error("text")]
struct DisplayOnly;
#[derive(NotSensitive)]
#[redactable(output = json)]
struct Public;
#[derive(NotSensitiveDisplay)]
#[redactable(output = json)]
struct PublicDisplay;
#[derive(Sensitive)]
struct Field {
    #[redactable(output = json)]
    #[not_sensitive]
    field: String,
}
#[derive(SensitiveDual)]
enum Variant {
    #[redactable(output = json)]
    #[error("unit")]
    Unit,
}
fn main() {}
