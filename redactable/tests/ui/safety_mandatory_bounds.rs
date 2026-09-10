use redactable::{NotSensitive, Sensitive, SensitiveDual};
#[derive(Sensitive, serde::Serialize)]
struct MissingClone {
    #[not_sensitive]
    public: String,
}
#[derive(Clone, Sensitive)]
struct MissingSerialize {
    #[not_sensitive]
    public: String,
}
#[derive(SensitiveDual, serde::Serialize)]
#[error("summary")]
struct DualMissingClone {
    #[not_sensitive]
    public: String,
}
#[derive(NotSensitive)]
struct PublicMissingSerialize {
    #[allow(dead_code)]
    public: String,
}
fn main() {}
