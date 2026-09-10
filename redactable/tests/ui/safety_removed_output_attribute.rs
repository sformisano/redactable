use redactable::{NotSensitive, NotSensitiveDisplay, Sensitive, SensitiveDisplay, SensitiveDual};
#[derive(Sensitive)]
#[redactable(output = json)]
struct StructuralContainer;
#[derive(SensitiveDisplay)]
#[redactable(output = json)]
#[error("text")]
struct DisplayContainer;
#[derive(SensitiveDual)]
#[redactable(output = json)]
#[error("text")]
struct DualContainer;
#[derive(NotSensitive)]
#[redactable(output = json)]
struct PublicContainer;
#[derive(NotSensitiveDisplay)]
#[redactable(output = json)]
struct PublicDisplayContainer;
#[derive(Sensitive)]
struct FieldPosition {
    #[redactable(output = json)]
    #[not_sensitive]
    field: String,
}
#[derive(SensitiveDual)]
enum VariantPosition {
    #[redactable(output = json)]
    #[error("unit")]
    Unit,
}
fn main() {}
