use redactable::{Sensitive, SensitiveDisplay, SensitiveDual};
#[derive(Clone, serde::Serialize, SensitiveDual)]
#[error("{next}")]
struct Recursive {
    #[redactable(recursive)]
    next: Option<Box<Recursive>>,
    raw: String,
}
#[derive(SensitiveDisplay)]
#[error("{pair}")]
struct RecursiveTuple {
    #[redactable(recursive)]
    pair: Option<(Box<RecursiveTuple>, String)>,
}
#[derive(Clone, serde::Serialize, Sensitive)]
struct StructuralTuple {
    #[redactable(recursive)]
    pair: Option<(Box<StructuralTuple>, String)>,
}
fn main() {}
