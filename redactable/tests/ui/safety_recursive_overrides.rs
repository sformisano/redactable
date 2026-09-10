use redactable::{Secret, Sensitive, SensitiveDisplay, SensitiveDual};
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
#[derive(SensitiveDisplay)]
#[error("{value} {raw}")]
struct Legacy {
    #[sensitive(Secret)]
    #[redactable(legacy_formatting)]
    value: Option<String>,
    raw: String,
}
#[derive(SensitiveDisplay)]
#[error("{value} {raw}")]
struct Generated {
    #[sensitive(Secret)]
    #[redactable(generated_formatting)]
    value: Vec<String>,
    raw: String,
}
fn main() {}
