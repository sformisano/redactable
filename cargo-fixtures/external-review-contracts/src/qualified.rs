use redactable::{RedactableMapper, RedactableWithMapper};

pub struct Node<T>(pub T);

impl<T: RedactableWithMapper> RedactableWithMapper for Node<T> {
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        Self(self.0.redact_with(mapper))
    }
}
