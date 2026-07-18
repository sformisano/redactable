use redactable::{Redactable, RedactableMapper, RedactableWithMapper, Sensitive};

pub mod other {
    use super::{RedactableMapper, RedactableWithMapper};

    pub struct Node<T>(pub T);

    impl<T: RedactableWithMapper> RedactableWithMapper for Node<T> {
        fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
            Self(self.0.redact_with(mapper))
        }
    }
}

#[derive(Sensitive)]
struct Node<T> {
    child: other::Node<T>,
}

pub fn exercise() {
    let _ = Node {
        child: other::Node(String::from("secret")),
    }
    .redact();
}
