use redactable::{Sensitive, SensitiveDual};
#[derive(Sensitive, serde::Serialize)]
#[redactable(output = json)]
struct MissingClone {
    #[not_sensitive]
    public: String,
}
#[derive(Clone, Sensitive)]
#[redactable(output = json)]
struct MissingSerialize {
    #[not_sensitive]
    public: String,
}
#[derive(SensitiveDual, serde::Serialize)]
#[redactable(output = json)]
#[error("summary")]
struct DualMissingClone {
    #[not_sensitive]
    public: String,
}
fn main() {}
