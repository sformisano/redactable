//! Exercise nested slog fields through a drain that also retains them for later.

#![cfg(feature = "slog")]

use std::{
    cell::Cell,
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
};

use redactable::{
    BypassDebugRedaction, BypassDisplayRedaction, BypassJsonRedaction, RedactedValue, ToRedacted,
    logging::Sink,
};
use redactable_test_fixtures::GenericDualFixture;
use serde_json::{Map, Value, json};
use slog::{Drain, KV, Key, Level, Logger, Never, OwnedKVList, Record, SerdeValue, Serializer};

#[derive(Default)]
struct Fields {
    live: Map<String, Value>,
    queued: Vec<(Key, Box<dyn SerdeValue + Send>)>,
}

impl Serializer for Fields {
    fn emit_arguments(&mut self, key: Key, value: &fmt::Arguments<'_>) -> slog::Result {
        self.live.insert(key.to_string(), json!(value.to_string()));
        Ok(())
    }

    fn emit_serde(&mut self, key: Key, value: &dyn SerdeValue) -> slog::Result {
        self.live.insert(
            key.to_string(),
            serde_json::to_value(value.as_serde()).unwrap(),
        );
        self.queued.push((key, value.to_sendable()));
        Ok(())
    }
}

#[derive(Default)]
struct Capture(Arc<Mutex<Vec<(Level, String, Fields)>>>);

impl Drain for Capture {
    type Ok = ();
    type Err = Never;

    fn log(&self, record: &Record<'_>, values: &OwnedKVList) -> Result<(), Never> {
        let mut fields = Fields::default();
        record.kv().serialize(record, &mut fields).unwrap();
        values.serialize(record, &mut fields).unwrap();
        self.0
            .lock()
            .unwrap()
            .push((record.level(), record.msg().to_string(), fields));
        Ok(())
    }
}

#[test]
fn native_level_filter_decides_whether_checked_fields_run() {
    let logger = Logger::root(slog::Discard, slog::o!());
    let calls = Cell::new(0);
    slog::debug!(logger, "native"; "probe" => { calls.set(calls.get() + 1); 1_u32 });
    let native_calls = calls.replace(0);

    let sink = Sink::Slog(logger);
    redactable::debug!(sink, probe = { calls.set(calls.get() + 1) }; "checked");
    assert_eq!(calls.get(), native_calls);
}

#[cfg(all(feature = "log", feature = "tracing"))]
#[test]
fn one_callsite_sends_each_event_only_to_the_selected_receiver() {
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    use tracing::{Event, Metadata, Subscriber, span};

    #[derive(Default)]
    struct Count(AtomicUsize);

    impl log::Log for Count {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }
        fn log(&self, _: &log::Record<'_>) {
            self.0.fetch_add(1, Relaxed);
        }
        fn flush(&self) {}
    }

    impl Subscriber for Count {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn event(&self, _: &Event<'_>) {
            self.0.fetch_add(1, Relaxed);
        }
        fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }
        fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
        fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
        fn enter(&self, _: &span::Id) {}
        fn exit(&self, _: &span::Id) {}
    }

    static LOG: Count = Count(AtomicUsize::new(0));
    log::set_logger(&LOG).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    let capture = Capture::default();
    let slog_records = Arc::clone(&capture.0);
    let logger = Logger::root(capture, slog::o!());
    let tracing_events = Arc::new(Count::default());
    tracing::subscriber::with_default(Arc::clone(&tracing_events), || {
        for (sink, expected) in [
            (Sink::Log, [1, 0, 0]),
            (Sink::Slog(logger), [1, 1, 0]),
            (Sink::Tracing, [1, 1, 1]),
        ] {
            redactable::info!(sink, value = (); "routed");
            assert_eq!(
                [
                    LOG.0.load(Relaxed),
                    slog_records.lock().unwrap().len(),
                    tracing_events.0.load(Relaxed)
                ],
                expected
            );
        }
    });
}

#[test]
fn nested_and_queued_fields_use_the_same_declared_projection() {
    const SECRET: &str = "private-slog-token-5101";
    let capture = Capture::default();
    let records = Arc::clone(&capture.0);
    let sink = Sink::Slog(Logger::root(capture, slog::o!()));
    let calls = Cell::new(0);
    {
        struct Counted<'a>(&'a Cell<usize>);

        impl ToRedacted for Counted<'_> {
            fn to_redacted(&self) -> RedactedValue {
                self.0.set(self.0.get() + 1);
                GenericDualFixture {
                    label: "sign-in",
                    secret: SECRET.into(),
                }
                .to_redacted()
            }
        }

        let producer = Counted(&calls);
        let saved = producer.to_redacted();
        let public = ["web", "app"];
        let invalid_keys = BTreeMap::from([((1, 2), SECRET)]);
        redactable::warn!(sink,
            account = &saved,
            selected:% = &producer,
            debug:? = &producer,
            comment = BypassDisplayRedaction("reviewed"),
            detail:? = BypassDebugRedaction("public"),
            roles = BypassJsonRedaction(&public),
            absent = None::<()>,
            failed = BypassJsonRedaction(&invalid_keys);
            "checked {{login}}"
        );
    }

    let (level, message, fields) = records.lock().unwrap().pop().unwrap();
    assert_eq!(level, Level::Warning);
    assert_eq!(message, "checked {login}");
    assert_eq!(calls.get(), 3);
    assert_eq!(
        Value::Object(fields.live.clone()),
        json!({
            "account": {"label": "sign-in", "secret": "[REDACTED]"},
            "selected": "sign-in: [REDACTED]", "debug": "sign-in: [REDACTED]",
            "comment": {"message": "reviewed"}, "detail": "\"public\"",
            "roles": ["web", "app"], "absent": null, "failed": "[REDACTED]"
        }),
    );

    // Replay the queued values after the snapshot and the producer have gone out of scope.
    let args = format_args!("");
    let metadata = slog::record_static!(Level::Warning, "");
    let record = Record::new(&metadata, &args, slog::b!());
    let mut replay = Fields::default();
    assert_eq!(fields.queued.len(), 5);
    for (key, queued) in fields.queued {
        queued.serialize(&record, key, &mut replay).unwrap();
    }
    assert_eq!(replay.live.len(), 5);
    for (key, value) in replay.live {
        assert_eq!(fields.live[&key], value);
    }
    assert!(
        fields
            .live
            .values()
            .all(|value| !value.to_string().contains(SECRET))
    );
}
