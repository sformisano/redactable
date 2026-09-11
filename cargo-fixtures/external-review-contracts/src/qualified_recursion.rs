use redactable::__private::DeclaredFormatting;
// Qualified type paths intentionally exercise derive name resolution.
use redactable::{Redactable, RedactableWithFormatter, Sensitive, SensitiveDisplay, SensitiveDual};
use redactable::{Secret, SensitiveValue};

#[derive(Clone, serde::Serialize, Sensitive)]
pub struct SelfNode<T: Redactable> {
    value: T,
    next: Option<Box<self::SelfNode<T>>>,
}

#[derive(SensitiveDisplay)]
#[error("self {value:?} {next:?}")]
pub struct SelfDisplayNode<T: DeclaredFormatting> {
    value: T,
    next: Option<Box<self::SelfDisplayNode<T>>>,
}

#[derive(Clone, serde::Serialize, SensitiveDual)]
#[error("dual {value:?} {next:?}")]
pub struct SelfDualNode<T: Redactable + DeclaredFormatting> {
    value: T,
    next: Option<Box<self::SelfDualNode<T>>>,
}

pub mod tree {
    use redactable::__private::DeclaredFormatting;
    use redactable::{
        Redactable, RedactableWithFormatter, Secret, Sensitive, SensitiveDisplay, SensitiveValue,
    };

    #[derive(Clone, serde::Serialize, Sensitive)]
    pub enum Tree<T: Redactable> {
        Branch(T, Box<self::Tree<T>>),
        Leaf(T),
    }

    #[derive(SensitiveDisplay)]
    pub enum DisplayTree<T: DeclaredFormatting> {
        #[error("branch {0:?} {1:?}")]
        Branch(T, Box<self::DisplayTree<T>>),
        #[error("leaf {0:?}")]
        Leaf(T),
    }

    pub fn exercise() {
        let _ = Tree::Branch(
            SensitiveValue::<String, Secret>::from(String::from("secret")),
            Box::new(Tree::Leaf(SensitiveValue::<String, Secret>::from(
                String::from("secret"),
            ))),
        )
        .redact();
        let _ = DisplayTree::Branch(
            SensitiveValue::<String, Secret>::from(String::from("secret")),
            Box::new(DisplayTree::Leaf(SensitiveValue::<String, Secret>::from(
                String::from("secret"),
            ))),
        )
        .redacted_display()
        .to_string();
    }
}

pub fn exercise() {
    let _ = SelfNode {
        value: SensitiveValue::<String, Secret>::from(String::from("secret")),
        next: None,
    }
    .redact();
    let _ = SelfDisplayNode {
        value: SensitiveValue::<String, Secret>::from(String::from("secret")),
        next: None,
    }
    .redacted_display()
    .to_string();
    let _ = SelfDualNode {
        value: SensitiveValue::<String, Secret>::from(String::from("secret")),
        next: None,
    }
    .redact();
    tree::exercise();
}
