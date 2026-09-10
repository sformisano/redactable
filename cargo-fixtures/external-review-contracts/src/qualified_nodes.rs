// Qualified type paths intentionally exercise derive name resolution.
use redactable::Sensitive;

use crate::qualified;

#[derive(Clone, serde::Serialize, Sensitive)]
pub struct QualifiedNode<T> {
    pub child: qualified::Node<T>,
}

pub type QualifiedAlias<T> = qualified::Node<T>;

#[derive(Clone, serde::Serialize, Sensitive)]
pub struct AliasQualifiedNode<T> {
    pub child: QualifiedAlias<T>,
}
