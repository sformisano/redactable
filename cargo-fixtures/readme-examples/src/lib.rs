//! Consumer-crate harness for the repository README examples.

#![doc = include_str!("../../../README.md")]

#[doc = include_str!("../../../docs/reference.md")]
pub mod reference {}

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
};
use tracing::{
    Event, Id, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Record},
};

#[derive(Clone)]
struct Capture(Arc<Mutex<BTreeMap<String, String>>>);

impl Visit for Capture {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0
            .lock()
            .unwrap()
            .insert(field.name().into(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0
            .lock()
            .unwrap()
            .insert(field.name().into(), value.into());
    }

    fn record_value(&mut self, field: &Field, value: valuable::Value<'_>) {
        if let valuable::Value::Structable(value) = value {
            let mut fields = ValuableFields(BTreeMap::new());
            valuable::Valuable::visit(value, &mut fields);
            self.0.lock().unwrap().insert(
                field.name().into(),
                serde_json::to_string(&fields.0).unwrap(),
            );
        } else {
            self.record_debug(field, &value);
        }
    }
}

struct ValuableFields(BTreeMap<String, String>);

impl valuable::Visit for ValuableFields {
    fn visit_value(&mut self, _: valuable::Value<'_>) {}

    fn visit_named_fields(&mut self, values: &valuable::NamedValues<'_>) {
        for (field, value) in values.iter() {
            let text = match value {
                valuable::Value::String(value) => (*value).into(),
                _ => format!("{value:?}"),
            };
            self.0.insert(field.name().into(), text);
        }
    }
}

impl Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        event.record(&mut self.clone());
    }
}

/// Captures the actual fields emitted by a README tracing example.
pub fn capture_tracing(record: impl FnOnce()) -> BTreeMap<String, String> {
    let fields = Arc::new(Mutex::new(BTreeMap::new()));
    tracing::subscriber::with_default(Capture(fields.clone()), record);
    fields.lock().unwrap().clone()
}
