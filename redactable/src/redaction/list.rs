//! Item-limited JSON output for an explicitly selected slice.

use std::num::NonZeroUsize;

use serde_json::Value;

use super::output::{RedactedValue, ToRedacted};

/// Logs at most an explicit number of slice items as JSON.
///
/// The output is `{"items":[...],"omitted":count}`. The list requests each
/// included item's JSON once in slice order and skips the remaining items.
/// A text-only producer contributes `{"message": "…"}`, including for empty
/// text. A producer with stored JSON contributes that value.
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
        let items: Value = self.items[..included]
            .iter()
            .map(RedactedValue::json_from)
            .collect();
        RedactedValue::from_json(Value::from_iter([
            ("items", items),
            ("omitted", (self.items.len() - included).into()),
        ]))
    }
}
