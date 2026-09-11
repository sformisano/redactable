// Qualified type paths intentionally exercise derive name resolution.
use redactable::{Redactable, Sensitive};
use redactable::{Secret, SensitiveValue};

pub mod other {
    use redactable::{Redactable, RedactableMapper, RedactableWithMapper};

    #[derive(Clone, serde::Serialize)]
    pub struct Node<T>(pub T);

    impl<T: RedactableWithMapper> RedactableWithMapper for Node<T> {
        fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
            Self(self.0.redact_with(mapper))
        }
    }
    impl<T: Redactable> Redactable for Node<T> {}
}

#[derive(Clone, serde::Serialize, Sensitive)]
struct Node<T: Redactable> {
    child: other::Node<T>,
}

pub fn exercise() {
    use self::other::Node as OtherNode;

    let _ = Node {
        child: OtherNode(SensitiveValue::<String, Secret>::from(String::from(
            "secret",
        ))),
    }
    .redact();
}
