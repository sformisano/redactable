//! Item-limited JSON output for an explicitly selected slice.

use std::num::NonZeroUsize;

use serde_json::json;

use super::output::{RedactedValue, ToRedacted};

/// Logs at most an explicit number of slice items as JSON.
///
/// The output is `{"items":[...],"omitted":count}`. Each included producer runs
/// exactly once in slice order. Every item is read as JSON, so a text-only
/// producer contributes `{"message": "…"}`, including for empty text; a JSON
/// producer contributes its JSON value. Omitted producers never run. The
/// omitted count is deliberately visible.
///
/// The limit bounds item-producer calls only. It does not bound total bytes,
/// nesting depth, allocations, or the work performed by an included policy.
///
/// ```
/// use std::num::NonZeroUsize;
/// use redactable::{BypassDisplayRedaction, RedactedList, ToRedacted};
/// use serde_json::json;
///
/// let items = [BypassDisplayRedaction("public"), BypassDisplayRedaction("other")];
/// let value = RedactedList::new(&items, NonZeroUsize::new(1).unwrap()).to_redacted();
/// assert_eq!(value.json(), json!({
///     "items": [{"message": "public"}], "omitted": 1
/// }));
/// ```
#[derive(Clone, Copy)]
pub struct RedactedList<'a, T> {
    items: &'a [T],
    limit: NonZeroUsize,
}

impl<'a, T: ToRedacted> RedactedList<'a, T> {
    /// Borrows the slice and records the item limit without running producers.
    #[must_use]
    pub fn new(items: &'a [T], limit: NonZeroUsize) -> Self {
        Self { items, limit }
    }
}

impl<T: ToRedacted> ToRedacted for RedactedList<'_, T> {
    fn to_redacted(&self) -> RedactedValue {
        let included = self.items.len().min(self.limit.get());
        let items: Vec<_> = self.items[..included]
            .iter()
            .map(|item| item.to_redacted().json())
            .collect();
        RedactedValue::from_json(json!({
            "items": items,
            "omitted": self.items.len() - included,
        }))
    }
}
