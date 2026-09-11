// Qualified type paths intentionally exercise derive name resolution.
use redactable::{Redactable, Sensitive};

use crate::qualified;

#[derive(Clone, serde::Serialize, Sensitive)]
pub struct QualifiedNode<T: Redactable> {
    pub child: qualified::Node<T>,
}

pub type QualifiedAlias<T> = qualified::Node<T>;

#[derive(Clone, serde::Serialize, Sensitive)]
pub struct AliasQualifiedNode<T: Redactable> {
    pub child: QualifiedAlias<T>,
}
