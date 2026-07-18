//! Regressions for explicitly non-sensitive tracing certification.

#![cfg(feature = "tracing")]

use std::{
    fmt,
    sync::{Arc, Mutex},
};

use redactable::{NotSensitive, NotSensitiveExt, tracing::TracingRedacted};
use tracing::{
    Event, Id, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Record},
    subscriber::with_default,
};

#[derive(Clone, Default)]
struct CapturingSubscriber {
    fields: Arc<Mutex<Vec<(String, String)>>>,
}

struct CapturingVisitor<'a> {
    fields: &'a mut Vec<(String, String)>,
}

impl Visit for CapturingVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.fields
            .push((field.name().to_owned(), format!("{value:?}")));
    }
}

impl Subscriber for CapturingSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut fields = self.fields.lock().expect("capture lock should be healthy");
        event.record(&mut CapturingVisitor {
            fields: &mut fields,
        });
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

#[test]
fn not_sensitive_wrapper_is_tracing_certified_without_certifying_the_raw_type() {
    fn assert_tracing_certified<T: TracingRedacted>(_: &T) {}

    fn record_certified<O, B>(owned: &O, borrowed: &B)
    where
        O: TracingRedacted + fmt::Debug,
        B: TracingRedacted + fmt::Debug,
    {
        tracing::info!(owned = ?owned, borrowed = ?borrowed);
    }

    const RAW_VALUE: &str = "declared-safe-tracing-value-665d";
    let value = RAW_VALUE.to_owned();
    let owned = NotSensitive(value.clone());
    let borrowed = value.not_sensitive();
    assert_tracing_certified(&owned);
    assert_tracing_certified(&borrowed);

    let subscriber = CapturingSubscriber::default();
    let capture = subscriber.clone();
    with_default(subscriber, || record_certified(&owned, &borrowed));

    let fields = capture
        .fields
        .lock()
        .expect("capture lock should be healthy");
    let expected = format!("{RAW_VALUE:?}");
    for name in ["owned", "borrowed"] {
        let (_, value) = fields
            .iter()
            .find(|(field, _)| field == name)
            .unwrap_or_else(|| panic!("missing captured {name} field"));
        assert_eq!(value, &expected);
    }
}
