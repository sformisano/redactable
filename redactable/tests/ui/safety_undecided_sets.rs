use redactable::{Sensitive, SensitiveDisplay};
use std::collections::{BTreeSet, HashSet};
#[derive(serde::Serialize, Clone, Sensitive)]
struct HashTraversal {
    value: HashSet<String>,
}
#[derive(serde::Serialize, Clone, Sensitive)]
struct TreeTraversal {
    value: BTreeSet<String>,
}
#[derive(SensitiveDisplay)]
#[error("{value}")]
struct HashFormatting {
    value: HashSet<String>,
}
#[derive(SensitiveDisplay)]
#[error("{value}")]
struct TreeFormatting {
    value: BTreeSet<String>,
}
fn main() {}
