use redactable::{Sensitive, SensitiveDisplay};
use std::collections::{BTreeSet, HashSet};
#[derive(Clone, Sensitive)]
struct HashTraversal {
    value: HashSet<String>,
}
#[derive(Clone, Sensitive)]
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
