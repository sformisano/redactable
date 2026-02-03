//! Redaction traversal for cell-like containers.

use crate::redaction::{redact::RedactableMapper, traits::RedactableContainer};

// =============================================================================
// Cell implementations
// =============================================================================

impl<T> RedactableContainer for std::cell::RefCell<T>
where
    T: RedactableContainer,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        std::cell::RefCell::new(self.into_inner().redact_with(mapper))
    }
}

impl<T> RedactableContainer for std::cell::Cell<T>
where
    T: RedactableContainer + Copy,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        std::cell::Cell::new(self.get().redact_with(mapper))
    }
}
