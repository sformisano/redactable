//! The raw JSON protocol can introduce objects without calling Serde's map methods.

#![cfg(feature = "mask-map-keys")]

use redactable::{Sensitive, ToRedacted};
use serde::Serialize;
use serde_json::{Value, json, value::RawValue};

const PRIVATE_KEY: &str = "customer-key-691374";
const NESTED_KEY: &str = "billing-key-657891";

#[derive(Clone, Serialize, Sensitive)]
struct Report {
    #[not_sensitive]
    region: String,
    #[not_sensitive]
    counts: Box<RawValue>,
}

fn report() -> Report {
    Report {
        region: "west".into(),
        counts: RawValue::from_string(format!(
            r#"{{"{PRIVATE_KEY}":[{{"{NESTED_KEY}":17}},null,true,"active",0.25]}}"#
        ))
        .unwrap(),
    }
}

fn expected() -> Value {
    json!({"region":"west","counts":{
        "[REDACTED-KEY-0]":[{"[REDACTED-KEY-0]":17},null,true,"active",0.25]
    }})
}

#[test]
fn snapshot_masks_keys_in_raw_objects_and_arrays() {
    let saved = report().to_redacted();
    assert_eq!(saved.json(), expected());
    assert_eq!(serde_json::to_value(&saved).unwrap(), expected());
}

#[cfg(feature = "log")]
#[test]
fn checked_log_masks_raw_keys_in_the_emitted_record() {
    use std::sync::Mutex;

    struct Capture(Mutex<Vec<Value>>);
    impl log::Log for Capture {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }
        fn log(&self, record: &log::Record<'_>) {
            let report = record.key_values().get("report".into()).unwrap();
            self.0.lock().unwrap().push(json!({
                "msg": record.args().to_string(),
                "report": report,
            }));
        }
        fn flush(&self) {}
    }

    static LOGGER: Capture = Capture(Mutex::new(Vec::new()));
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    let report = report();
    redactable::info!(report; "counts");
    let records = LOGGER.0.lock().unwrap();
    assert_eq!(
        records.as_slice(),
        [json!({"msg":"counts","report":expected()})]
    );
    let emitted = serde_json::to_string(&*records).unwrap();
    assert!(!emitted.contains(PRIVATE_KEY));
    assert!(!emitted.contains(NESTED_KEY));
}

#[test]
fn malformed_raw_fragments_fall_back_for_the_whole_report() {
    use serde::ser::SerializeStruct;

    #[derive(Clone, Debug)]
    struct Malformed(Option<&'static str>);

    impl Serialize for Malformed {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            const RAW: &str = "$serde_json::private::RawValue";
            let mut raw = serializer.serialize_struct(RAW, 1)?;
            if let Some(text) = self.0 {
                raw.serialize_field(RAW, text)?;
            }
            raw.end()
        }
    }

    #[derive(Clone, Serialize, Sensitive)]
    struct Input {
        #[not_sensitive]
        id: u32,
        #[not_sensitive]
        raw: Malformed,
    }

    for raw in [Malformed(Some("[invalid")), Malformed(None)] {
        assert_eq!(Input { id: 12, raw }.to_redacted().json(), "[REDACTED]");
    }
}
