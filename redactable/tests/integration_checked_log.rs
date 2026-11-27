//! This test binary owns its global logger and level filter.

#![cfg(feature = "log")]

use std::{cell::Cell, fmt, sync::Mutex};

use ::log::{Level, LevelFilter, Log, Metadata, Record};
use redactable::{
    BypassDebugRedaction, BypassDisplayRedaction, BypassJsonRedaction, NotSensitive, RedactedValue,
    ToRedacted, debug, error, info as checked_info, logging::Sink, trace, warn,
};
use redactable_test_fixtures::{FixtureUser, GenericDualFixture};
use serde::Serialize;
use serde_json::{Value, json};

#[path = "support/log_capture.rs"]
mod log_capture;

#[derive(Debug)]
struct Captured {
    level: Level,
    target: String,
    file: Option<String>,
    line: Option<u32>,
    message: String,
    fields: Value,
}

struct Capture(Mutex<Vec<Captured>>);

impl Log for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &Record<'_>) {
        self.0.lock().unwrap().push(Captured {
            level: record.level(),
            target: record.target().into(),
            file: record.file().map(str::to_owned),
            line: record.line(),
            message: record.args().to_string(),
            fields: log_capture::fields(record),
        });
    }

    fn flush(&self) {}
}

#[derive(Debug, Serialize)]
struct Projection<'a> {
    token: &'a str,
    #[serde(skip)]
    calls: Cell<usize>,
}

impl fmt::Display for Projection<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token)
    }
}

impl ToRedacted for Projection<'_> {
    fn to_redacted(&self) -> RedactedValue {
        self.calls.set(self.calls.get() + 1);
        GenericDualFixture {
            label: "selected",
            secret: self.token.to_owned(),
        }
        .to_redacted()
    }
}

#[derive(Clone, Debug, NotSensitive, Serialize)]
struct Outcome {
    accepted: bool,
}

#[test]
fn sink_selection_can_return_early_or_await_in_a_send_future() {
    fn log_if_configured(sink: Option<&Sink>) -> Option<()> {
        checked_info!(sink?, "ready");
        Some(())
    }
    assert_eq!(log_if_configured(None), None);

    fn require_send(_: impl Send) {}
    require_send(async {
        checked_info!(std::future::ready(Sink::Log).await, "ready");
    });
}

#[test]
fn checked_levels_send_declared_fields_and_preserve_the_call_site() {
    static LOG: Capture = Capture(Mutex::new(Vec::new()));
    ::log::set_logger(&LOG).unwrap();
    ::log::set_max_level(LevelFilter::Trace);

    let secret = "checked-log-private-token-5362";
    let user = FixtureUser {
        name: "Alice".into(),
        api_key: secret.into(),
    };
    let saved = user.to_redacted();
    let projection = Projection {
        token: secret,
        calls: Cell::new(0),
    };
    let calls = Cell::new(0);
    let select = || {
        calls.set(calls.get() + 1);
        &projection
    };

    let sink = Sink::Log;
    let selections = Cell::new(0);
    let select_sink = || {
        selections.set(selections.get() + 1);
        &sink
    };
    let source_line = line!() + 1;
    checked_info!(select_sink(),
        user = &user, outcome = Outcome { accepted: true }, cached = &saved,
        data = select(), selected_display:% = select(), selected_debug:? = select(),
        text = BypassDisplayRedaction("public text"),
        display:% = BypassDisplayRedaction("public display"),
        debug:? = BypassDebugRedaction("public debug"),
        roles = BypassJsonRedaction(&["reader", "writer"]);
        "signed in {{audit}}"
    );
    error!(sink, "error");
    warn!(sink, "warn");
    debug!(sink, "debug");
    trace!(sink, "trace");
    ::log::set_max_level(LevelFilter::Warn);
    checked_info!(sink, data = select(); "disabled");

    let records = LOG.0.lock().unwrap();
    let first = &records[0];
    let expected_user = json!({"name": "Alice", "api_key": "[REDACTED]"});
    assert_eq!(
        first.fields,
        json!({
            "user": expected_user, "outcome": {"accepted": true}, "cached": expected_user,
            "data": {"label": "selected", "secret": "[REDACTED]"},
            "selected_display": "selected: [REDACTED]", "selected_debug": "selected: [REDACTED]",
            "text": {"message": "public text"}, "display": "public display",
            "debug": "\"public debug\"", "roles": ["reader", "writer"]
        })
    );
    assert_eq!(first.target, module_path!());
    assert_eq!(first.file.as_deref(), Some(file!()));
    assert_eq!(first.line, Some(source_line));
    assert_eq!(
        records
            .iter()
            .map(|r| (r.level, r.message.as_str()))
            .collect::<Vec<_>>(),
        [
            (Level::Info, "signed in {audit}"),
            (Level::Error, "error"),
            (Level::Warn, "warn"),
            (Level::Debug, "debug"),
            (Level::Trace, "trace")
        ]
    );
    assert_eq!(calls.get(), 3);
    assert_eq!(projection.calls.get(), 3);
    assert_eq!(selections.get(), 1);
    assert!(!format!("{records:?}").contains(secret));
}
