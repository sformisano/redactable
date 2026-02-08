//! Redaction traversal for cell-like containers.

use crate::redaction::{redact::RedactableMapper, traits::RedactableWithMapper};

// =============================================================================
// Cell implementations
// =============================================================================

impl<T> RedactableWithMapper for std::cell::RefCell<T>
where
    T: RedactableWithMapper,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        std::cell::RefCell::new(self.into_inner().redact_with(mapper))
    }
}

impl<T> RedactableWithMapper for std::cell::Cell<T>
where
    T: RedactableWithMapper + Copy,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        std::cell::Cell::new(self.get().redact_with(mapper))
    }
}
