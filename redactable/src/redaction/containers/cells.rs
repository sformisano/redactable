//! Redaction traversal for cell-like containers.

use std::cell::{Cell, RefCell};

use crate::redaction::{redact::RedactableMapper, traits::RedactableWithMapper};

// =============================================================================
// Cell implementations
// =============================================================================

impl<T> RedactableWithMapper for RefCell<T>
where
    T: RedactableWithMapper,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        RefCell::new(self.into_inner().redact_with(mapper))
    }
}

impl<T> RedactableWithMapper for Cell<T>
where
    T: RedactableWithMapper + Copy,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        Cell::new(self.get().redact_with(mapper))
    }
}
