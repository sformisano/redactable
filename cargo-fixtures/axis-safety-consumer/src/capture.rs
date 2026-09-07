//! Real event capture matching Axis's
//! `crates/framework/public/infrastructure/src/observability/tracing/logger.rs`
//! at revision 14417ae77286e45a7d4dbbd8e674a9a6cc091397.

use std::{
    collections::BTreeMap,
    fmt::Debug,
    sync::{Arc, Mutex},
};

use serde_json::Value;
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

#[derive(Default)]
struct Visitor(BTreeMap<String, String>);

impl Visit for Visitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
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
        let mut visitor = Visitor::default();
        event.record(&mut visitor);
        self.0.lock().expect("capture lock").push(visitor.0);
    }
}

pub fn capture_fields(fields: Value) -> Value {
    let capture = Capture::default();
    // A thread-local subscriber avoids a global singleton across test cases.
    tracing::subscriber::with_default(capture.clone(), || {
        let axis_fields_json = fields.to_string();
        tracing::info!(message = "action completed", axis_fields_json = %axis_fields_json);
    });
    let events = capture.0.lock().expect("capture lock");
    assert_eq!(
        events.len(),
        1,
        "one tracing event must reach the subscriber"
    );
    assert_eq!(
        events[0].len(),
        2,
        "message and structured field are separate"
    );
    assert_eq!(events[0]["message"], "action completed");
    let captured = &events[0]["axis_fields_json"];
    serde_json::from_str(captured).expect("captured axis_fields_json must parse")
}
