//! Sink-value contracts: what each producer builds, and what both accessors answer.

use redactable::{BypassDebugRedaction, BypassDisplayRedaction, BypassTextRedaction, ToRedacted};

#[test]
fn explicit_text_values_preserve_bytes_and_debug() {
    let value = BypassDisplayRedaction("***ce").to_redacted();
    assert_eq!(value.text(), "***ce");
    assert_eq!(format!("{value:?}"), "RedactedValue { text: \"***ce\" }");
    assert_eq!(value.clone(), value.to_redacted());
    assert_eq!(
        BypassDebugRedaction("public").to_redacted().text(),
        "\"public\""
    );
    assert_eq!(BypassTextRedaction(String::new()).to_redacted().text(), "");
    assert_eq!(
        BypassTextRedaction("declined".into()).to_redacted().text(),
        "declined"
    );
}

mod json_value {
    use std::collections::{BTreeMap, BTreeSet};

    use redactable::{
        BypassJsonRedaction, BypassTextRedaction, Redactable, RedactableMapper,
        RedactableWithFormatter, RedactableWithMapper, RedactedValue, Secret, Sensitive,
        SensitiveDual, ToRedacted,
    };
    use serde::{Serialize, Serializer, ser::Error};
    use serde_json::{Value, json};

    #[derive(Clone, Serialize, SensitiveDual)]
    #[error("decision {approved}")]
    struct Decision {
        #[sensitive(Secret)]
        owner: String,
        #[not_sensitive]
        approved: bool,
    }

    // The same trait-bounded sink is used for real and deliberately wrong values.
    fn record<T: ToRedacted>(value: &T) -> Value {
        json!({ "result": value.to_redacted().json() })
    }

    fn assert_decision<T: ToRedacted>(value: &T) {
        assert_eq!(
            record(value),
            json!({"result":{"owner":"[REDACTED]","approved":true}})
        );
    }

    #[test]
    fn generated_json_reaches_sink_and_retains_dual_template_and_raw_transport() {
        let decision = Decision {
            owner: "Ada".into(),
            approved: true,
        };
        assert_decision(&decision);
        assert_eq!(decision.redacted_display().to_string(), "decision true");
        assert_eq!(
            serde_json::to_value(&decision).unwrap(),
            json!({"owner":"Ada","approved":true})
        );
    }

    #[test]
    fn a_dual_value_carries_both_representations_without_merging_them() {
        let value = Decision {
            owner: "Ada".into(),
            approved: true,
        }
        .to_redacted();
        assert_eq!(value.text(), "decision true");
        assert_eq!(value.json(), json!({"owner":"[REDACTED]","approved":true}));
        // Neither representation leaks into the other's shape.
        assert!(value.json().get("message").is_none());
        assert_ne!(
            value.json(),
            json!({"message":"decision true","owner":"[REDACTED]","approved":true})
        );
        let debug = format!("{value:?}");
        assert!(debug.starts_with("RedactedValue { text: \"decision true\", json: Object {"));
        assert!(debug.contains("\"owner\": String(\"[REDACTED]\")"));
    }

    #[test]
    fn text_only_and_json_only_values_adapt_instead_of_refusing() {
        let text = BypassTextRedaction("declined".into()).to_redacted();
        assert_eq!(text.text(), "declined");
        assert_eq!(text.json(), json!({"message": "declined"}));
        // Not a bare JSON string, which is what the 0.11 encoding produced.
        assert_ne!(text.json(), json!("declined"));
        assert_eq!(
            BypassTextRedaction(String::new()).to_redacted().json(),
            json!({"message": ""})
        );

        let raw = json!({"owner":"***ce"});
        let structured = BypassJsonRedaction(&raw).to_redacted();
        assert_eq!(structured.json(), raw);
        // Compact JSON text, not the `Debug` rendering of the JSON value.
        assert_eq!(structured.text(), "{\"owner\":\"***ce\"}");
        assert_ne!(structured.text(), format!("{raw:?}"));
        assert_eq!(
            format!("{structured:?}"),
            "RedactedValue { json: Object {\"owner\": String(\"***ce\")} }"
        );
    }

    #[test]
    fn selected_value_assertion_rejects_blank_missing_and_placeholder_results() {
        use std::panic::catch_unwind;

        assert!(catch_unwind(|| assert_decision(&BypassTextRedaction(String::new()))).is_err());
        assert!(
            catch_unwind(|| assert_decision(&BypassTextRedaction("[REDACTED]".into()))).is_err()
        );
        for wrong in [
            json!({"approved":true}),
            json!({"owner":"[REDACTED]"}),
            json!({"owner":"[REDACTED]","approved":false}),
            json!("[REDACTED]"),
            json!({"owner":"Ada","approved":true}),
        ] {
            assert!(catch_unwind(|| assert_decision(&BypassJsonRedaction(&wrong))).is_err());
        }
    }

    #[derive(Clone, Serialize, Sensitive)]
    enum Event {
        Empty,
        Named {
            #[sensitive(Secret)]
            token: String,
            #[not_sensitive]
            accepted: bool,
        },
        Count(#[sensitive(Secret)] u32),
    }

    #[test]
    fn every_enum_shape_retains_selected_policy_and_public_values() {
        assert_eq!(record(&Event::Empty), json!({"result":"Empty"}));
        assert_eq!(
            record(&Event::Named {
                token: "secret".into(),
                accepted: true
            }),
            json!({"result":{"Named":{"token":"[REDACTED]","accepted":true}}})
        );
        assert_eq!(record(&Event::Count(9)), json!({"result":{"Count":0}}));
    }

    #[derive(Clone, Serialize, Sensitive)]
    struct Collections {
        #[sensitive(Secret)]
        optional: Option<String>,
        #[sensitive(Secret)]
        map: BTreeMap<String, String>,
        #[sensitive(Secret)]
        set: BTreeSet<String>,
        opaque: Value,
    }

    #[test]
    fn optional_empty_map_keys_set_collapse_and_opaque_json_keep_their_contracts() {
        let populated = Collections {
            optional: Some("secret".into()),
            map: [("public-key".into(), "secret".into())].into(),
            set: ["first".into(), "second".into()].into(),
            opaque: json!({"arbitrary":[1,2]}),
        };
        assert_eq!(
            record(&populated),
            json!({"result":{"optional":"[REDACTED]","map":{"public-key":"[REDACTED]"},"set":["[REDACTED]"],"opaque":"[REDACTED]"}})
        );
        let empty = Collections {
            optional: None,
            map: BTreeMap::new(),
            set: BTreeSet::new(),
            opaque: Value::Null,
        };
        assert_eq!(
            record(&empty),
            json!({"result":{"optional":null,"map":{},"set":[],"opaque":"[REDACTED]"}})
        );
    }

    #[derive(Clone, Debug)]
    struct FailingSerializer;

    impl Serialize for FailingSerializer {
        fn serialize<S: Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
            Err(S::Error::custom("private serialization failure"))
        }
    }

    impl RedactableWithMapper for FailingSerializer {
        fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
            self
        }
    }

    impl Redactable for FailingSerializer {}

    #[derive(Clone, Sensitive)]
    struct CustomWire {
        #[sensitive(Secret)]
        secret: String,
    }

    impl Serialize for CustomWire {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&format!("wire:{}", self.secret))
        }
    }

    #[test]
    fn custom_serializer_observes_redacted_value_and_raw_transport_remains_separate() {
        let value = CustomWire {
            secret: "Ada".into(),
        };
        assert_eq!(record(&value), json!({"result":"wire:[REDACTED]"}));
        assert_eq!(serde_json::to_value(&value).unwrap(), json!("wire:Ada"));
    }

    #[derive(Clone, Sensitive)]
    struct FailingEvent {
        #[not_sensitive]
        secret: FailingSerializer,
    }

    impl Serialize for FailingEvent {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.secret.serialize(serializer)
        }
    }

    #[test]
    fn serialization_failure_closes_the_generated_and_explicit_json_paths() {
        let expected = json!("[REDACTED]");
        let event = FailingEvent {
            secret: FailingSerializer,
        };
        assert_eq!(event.to_redacted().json(), expected);
        assert_eq!(
            BypassJsonRedaction(&FailingSerializer).to_redacted().json(),
            expected
        );
        assert!(serde_json::to_value(FailingSerializer).is_err());
    }

    #[test]
    fn handwritten_producers_remain_supported() {
        struct Projection;
        impl ToRedacted for Projection {
            fn to_redacted(&self) -> RedactedValue {
                Decision {
                    owner: "Ada".into(),
                    approved: true,
                }
                .to_redacted()
            }
        }
        assert_decision(&Projection);
    }
}

#[cfg(feature = "slog")]
mod slog_value {
    use std::{
        cell::Cell,
        fmt::{Arguments, Formatter, Result as FmtResult},
        sync::{Arc, Mutex},
    };

    use redactable::{
        BypassJsonRedaction, BypassTextRedaction, RedactableWithFormatter, RedactedValue,
        ToRedacted, slog::SlogRedactedExt,
    };
    use serde_json::json;
    use slog::{
        Drain, Error as SlogError, KV, Key, Logger, OwnedKVList, Record, Result as SlogResult,
        Serializer,
    };

    struct Divergent {
        calls: Cell<usize>,
        json: bool,
    }

    impl RedactableWithFormatter for Divergent {
        fn fmt_redacted(&self, f: &mut Formatter<'_>) -> FmtResult {
            f.write_str("FORMATTER")
        }
    }
    impl ToRedacted for Divergent {
        fn to_redacted(&self) -> RedactedValue {
            self.calls.set(self.calls.get() + 1);
            if self.json {
                BypassJsonRedaction(&json!({"selected":true})).to_redacted()
            } else {
                BypassTextRedaction("SELECTED".into()).to_redacted()
            }
        }
    }

    struct Capture(Arc<Mutex<Vec<String>>>);
    struct TextSerializer<'a>(&'a mut Vec<String>);
    impl Serializer for TextSerializer<'_> {
        fn emit_arguments(&mut self, _key: Key, value: &Arguments<'_>) -> SlogResult {
            self.0.push(value.to_string());
            Ok(())
        }
    }
    impl Drain for Capture {
        type Ok = ();
        type Err = SlogError;
        fn log(&self, record: &Record<'_>, values: &OwnedKVList) -> SlogResult {
            let mut captured = self.0.lock().unwrap();
            let mut serializer = TextSerializer(&mut captured);
            record.kv().serialize(record, &mut serializer)?;
            values.serialize(record, &mut serializer)
        }
    }

    #[test]
    fn real_slog_drain_records_selected_text_once_even_when_formatter_disagrees() {
        for (json, expected) in [(false, "SELECTED"), (true, "{\"selected\":true}")] {
            let captured = Arc::new(Mutex::new(Vec::new()));
            let logger = Logger::root(Capture(captured.clone()).fuse(), slog::o!());
            let value = Divergent {
                calls: Cell::new(0),
                json,
            };
            slog::info!(logger, "result"; "result" => value.slog_redacted());
            assert_eq!(*captured.lock().unwrap(), [expected]);
            assert_eq!(value.calls.get(), 1);
        }
    }
}
