use redactable::{Redactable, RedactableWithFormatter, Sensitive, SensitiveDisplay, SensitiveDual};

#[derive(Sensitive)]
pub struct SelfNode<T> {
    value: T,
    next: Option<Box<self::SelfNode<T>>>,
}

#[derive(SensitiveDisplay)]
#[error("self {value:?} {next:?}")]
pub struct SelfDisplayNode<T> {
    value: T,
    next: Option<Box<self::SelfDisplayNode<T>>>,
}

#[derive(SensitiveDual)]
#[error("dual {value:?} {next:?}")]
pub struct SelfDualNode<T> {
    value: T,
    next: Option<Box<self::SelfDualNode<T>>>,
}

pub mod tree {
    use redactable::{Redactable, RedactableWithFormatter, Sensitive, SensitiveDisplay};

    #[derive(Sensitive)]
    pub enum Tree<T> {
        Branch(T, Box<self::Tree<T>>),
        Leaf(T),
    }

    #[derive(SensitiveDisplay)]
    pub enum DisplayTree<T> {
        #[error("branch {0:?} {1:?}")]
        Branch(T, Box<self::DisplayTree<T>>),
        #[error("leaf {0:?}")]
        Leaf(T),
    }

    pub fn exercise() {
        let _ = Tree::Branch(
            String::from("secret"),
            Box::new(Tree::Leaf(String::from("secret"))),
        )
        .redact();
        let _ = DisplayTree::Branch(
            String::from("secret"),
            Box::new(DisplayTree::Leaf(String::from("secret"))),
        )
        .redacted_display()
        .to_string();
    }
}

pub fn exercise() {
    let _ = SelfNode {
        value: String::from("secret"),
        next: None,
    }
    .redact();
    let _ = SelfDisplayNode {
        value: String::from("secret"),
        next: None,
    }
    .redacted_display()
    .to_string();
    let _ = SelfDualNode {
        value: String::from("secret"),
        next: None,
    }
    .redact();
    tree::exercise();
}
