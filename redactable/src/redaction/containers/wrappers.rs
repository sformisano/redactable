//! Redaction traversal for wrapper container types.

use crate::redaction::{redact::RedactableMapper, traits::RedactableContainer};

// =============================================================================
// Wrapper container implementations
// =============================================================================

impl<T> RedactableContainer for Option<T>
where
    T: RedactableContainer,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        self.map(|value| value.redact_with(mapper))
    }
}

impl<T, E> RedactableContainer for Result<T, E>
where
    T: RedactableContainer,
    E: RedactableContainer,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        match self {
            Ok(value) => Ok(value.redact_with(mapper)),
            Err(err) => Err(err.redact_with(mapper)),
        }
    }
}

impl<T> RedactableContainer for Vec<T>
where
    T: RedactableContainer,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        self.into_iter()
            .map(|value| value.redact_with(mapper))
            .collect()
    }
}

impl<T> RedactableContainer for Box<T>
where
    T: RedactableContainer,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        Box::new((*self).redact_with(mapper))
    }
}

impl<T> RedactableContainer for std::sync::Arc<T>
where
    T: RedactableContainer + Clone,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        std::sync::Arc::new((*self).clone().redact_with(mapper))
    }
}

impl<T> RedactableContainer for std::rc::Rc<T>
where
    T: RedactableContainer + Clone,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        std::rc::Rc::new((*self).clone().redact_with(mapper))
    }
}
