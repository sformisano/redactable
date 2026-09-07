use redactable::{Sensitive, SensitiveDual};
#[derive(Clone, Sensitive, serde::Serialize)]
#[redactable(output = json)]
struct Structural {
    #[not_sensitive]
    public: bool,
}
#[derive(Clone, SensitiveDual, serde::Serialize)]
#[redactable(output = json)]
#[error("summary")]
struct Dual {
    #[not_sensitive]
    public: bool,
}
fn main() {}
