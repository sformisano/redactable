use redactable::Sensitive;

use crate::qualified;

#[derive(Sensitive)]
pub struct QualifiedNode<T> {
    pub child: qualified::Node<T>,
}

pub type QualifiedAlias<T> = qualified::Node<T>;

#[derive(Sensitive)]
pub struct AliasQualifiedNode<T> {
    pub child: QualifiedAlias<T>,
}
