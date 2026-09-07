//! Selected output, transport, and captured sink contracts.

use redactable::{
    NotSensitiveDebug, NotSensitiveDisplay, RedactedOutputView, ToRedactedOutput,
    UncheckedRedactedSummary,
};

#[test]
fn explicit_text_outputs_preserve_bytes_and_debug() {
    let output = NotSensitiveDisplay("***ce").to_redacted_output();
    assert_eq!(output.view(), RedactedOutputView::Text("***ce"));
    assert_eq!(format!("{output:?}"), "Text(\"***ce\")");
    assert_eq!(output.clone(), output.to_redacted_output());
    assert_eq!(
        NotSensitiveDebug("public").to_redacted_output().view(),
        RedactedOutputView::Text("\"public\"")
    );
    assert_eq!(
        UncheckedRedactedSummary::new(String::new())
            .to_redacted_output()
            .view(),
        RedactedOutputView::Text("")
    );
    assert_eq!(
        UncheckedRedactedSummary::new("declined".into())
            .to_redacted_output()
            .view(),
        RedactedOutputView::Text("declined")
    );
}

#[cfg(feature = "json")]
mod json_output {
    use std::collections::{BTreeMap, BTreeSet};

    use redactable::{
        IntoRedactedJsonExt, NotSensitiveJsonExt, Redactable, RedactableMapper,
        RedactableWithFormatter, RedactableWithMapper, RedactedJsonExt, RedactedOutput,
        RedactedOutputView, Secret, Sensitive, SensitiveDual, ToRedactedOutput,
        UncheckedRedactedSummary,
    };
    use serde::{Serialize, Serializer, ser::Error};
    use serde_json::{Value, json};

    #[derive(Clone, Serialize, SensitiveDual)]
    #[redactable(output = json)]
    #[error("decision {approved}")]
    struct Decision {
        #[sensitive(Secret)]
        owner: String,
        #[not_sensitive]
        approved: bool,
    }

    // The same trait-bounded sink is used for real and deliberately wrong outputs.
    fn record<T: ToRedactedOutput>(value: &T) -> Value {
        match value.to_redacted_output().view() {
            RedactedOutputView::Json(value) => json!({"result": value}),
            RedactedOutputView::Text(value) => json!({"result": value}),
            _ => panic!("unsupported output representation"),
        }
    }

    fn assert_decision<T: ToRedactedOutput>(value: &T) {
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
        assert_eq!(
            decision.redacted_json().to_redacted_output(),
            decision.clone().into_redacted_json().to_redacted_output()
        );
    }

    #[test]
    fn selected_output_assertion_rejects_blank_missing_and_placeholder_results() {
        use std::panic::catch_unwind;

        assert!(
            catch_unwind(|| assert_decision(&UncheckedRedactedSummary::new(String::new())))
                .is_err()
        );
        assert!(
            catch_unwind(|| assert_decision(&UncheckedRedactedSummary::new("[REDACTED]".into())))
                .is_err()
        );
        assert!(
            catch_unwind(|| assert_decision(&json!({"approved":true}).not_sensitive_json()))
                .is_err()
        );
        assert!(
            catch_unwind(|| assert_decision(&json!({"owner":"[REDACTED]"}).not_sensitive_json()))
                .is_err()
        );
        assert!(
            catch_unwind(|| assert_decision(
                &json!({"owner":"[REDACTED]","approved":false}).not_sensitive_json()
            ))
            .is_err()
        );
        assert!(
            catch_unwind(|| assert_decision(&json!("[REDACTED]").not_sensitive_json())).is_err()
        );
        assert!(
            catch_unwind(|| assert_decision(
                &json!({"owner":"Ada","approved":true}).not_sensitive_json()
            ))
            .is_err()
        );
    }

    #[derive(Clone, Serialize, Sensitive)]
    #[redactable(output = json)]
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
    #[redactable(output = json)]
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

    #[derive(Clone)]
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
    #[redactable(output = json)]
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

    #[test]
    fn serialization_failure_closes_borrowing_consuming_and_explicit_json_paths() {
        let expected = json!("[REDACTED]");
        for output in [
            FailingSerializer.redacted_json().to_redacted_output(),
            FailingSerializer.into_redacted_json().to_redacted_output(),
            FailingSerializer.not_sensitive_json().to_redacted_output(),
        ] {
            assert_eq!(output.view(), RedactedOutputView::Json(&expected));
        }
        assert!(serde_json::to_value(FailingSerializer).is_err());
    }

    #[test]
    fn json_output_debug_and_handwritten_bridge_remain_supported() {
        struct Projection;
        impl ToRedactedOutput for Projection {
            fn to_redacted_output(&self) -> RedactedOutput {
                Decision {
                    owner: "Ada".into(),
                    approved: true,
                }
                .redacted_json()
                .to_redacted_output()
            }
        }
        assert_decision(&Projection);
        let output = json!({"owner":"***ce"})
            .not_sensitive_json()
            .to_redacted_output();
        assert_eq!(
            format!("{output:?}"),
            "Json(Object {\"owner\": String(\"***ce\")})"
        );
    }
}

#[cfg(feature = "slog")]
mod slog_output {
    use std::{
        cell::Cell,
        fmt::{Arguments, Formatter, Result as FmtResult},
        sync::{Arc, Mutex},
    };

    use redactable::{
        NotSensitiveJsonExt, RedactableWithFormatter, RedactedOutput, ToRedactedOutput,
        UncheckedRedactedSummary, slog::SlogRedactedDisplayExt,
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
    impl ToRedactedOutput for Divergent {
        fn to_redacted_output(&self) -> RedactedOutput {
            self.calls.set(self.calls.get() + 1);
            if self.json {
                json!({"selected":true})
                    .not_sensitive_json()
                    .to_redacted_output()
            } else {
                UncheckedRedactedSummary::new("SELECTED".into()).to_redacted_output()
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
            slog::info!(logger, "result"; "result" => value.slog_redacted_display());
            assert_eq!(*captured.lock().unwrap(), [expected]);
            assert_eq!(value.calls.get(), 1);
        }
    }
}
