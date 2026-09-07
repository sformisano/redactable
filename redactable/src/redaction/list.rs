//! Item-limited JSON output for an explicitly selected slice.

use std::num::NonZeroUsize;

use serde_json::json;

use super::output::{RedactedOutput, ToRedactedOutput};

/// Logs at most an explicit number of slice items as JSON.
///
/// The output is `{"items":[...],"omitted":count}`. Each included producer runs
/// exactly once in slice order. Text outputs become JSON strings, including
/// empty strings; JSON outputs retain their JSON values. Omitted producers
/// never run. The omitted count is deliberately visible.
///
/// The limit bounds item-producer calls only. It does not bound total bytes,
/// nesting depth, allocations, or the work performed by an included policy.
/// Available with the `json` feature.
///
/// ```
/// use std::num::NonZeroUsize;
/// use redactable::{NotSensitiveDisplay, RedactedList, RedactedOutputView, ToRedactedOutput};
/// use serde_json::json;
///
/// let items = [NotSensitiveDisplay("public"), NotSensitiveDisplay("other")];
/// let output = RedactedList::new(&items, NonZeroUsize::new(1).unwrap())
///     .to_redacted_output();
/// assert_eq!(output.view(), RedactedOutputView::Json(&json!({
///     "items": ["public"], "omitted": 1
/// })));
/// ```
#[derive(Clone, Copy)]
pub struct RedactedList<'a, T> {
    items: &'a [T],
    limit: NonZeroUsize,
}

impl<'a, T: ToRedactedOutput> RedactedList<'a, T> {
    /// Borrows the slice and records the item limit without running producers.
    #[must_use]
    pub fn new(items: &'a [T], limit: NonZeroUsize) -> Self {
        Self { items, limit }
    }
}

impl<T: ToRedactedOutput> ToRedactedOutput for RedactedList<'_, T> {
    fn to_redacted_output(&self) -> RedactedOutput {
        let included = self.items.len().min(self.limit.get());
        let items: Vec<_> = self.items[..included]
            .iter()
            .map(|item| item.to_redacted_output().into_json())
            .collect();
        RedactedOutput::json(json!({
            "items": items,
            "omitted": self.items.len() - included,
        }))
    }
}
