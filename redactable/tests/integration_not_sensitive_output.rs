//! Behavior and transport contracts for owned explicit-format wrappers.

use std::{
    collections::hash_map::DefaultHasher,
    fmt,
    hash::{Hash, Hasher},
};

use redactable::{
    NotSensitiveDebug, NotSensitiveDebugExt, NotSensitiveDisplay, NotSensitiveDisplayExt,
    RedactedOutput, ToRedactedOutput,
};

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Distinct(u8);

impl fmt::Debug for Distinct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "debug:{}", self.0)
    }
}

impl fmt::Display for Distinct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "display:{}", self.0)
    }
}

fn assert_copy<T: Copy>() {}

fn output<T: ToRedactedOutput>(value: &T) -> RedactedOutput {
    value.to_redacted_output()
}

#[test]
fn owned_wrappers_preserve_the_selected_format() {
    let debug = NotSensitiveDebug(Distinct(7));
    let display = NotSensitiveDisplay(Distinct(7));

    assert_eq!(output(&debug), RedactedOutput::Text("debug:7".to_owned()));
    assert_eq!(
        output(&display),
        RedactedOutput::Text("display:7".to_owned())
    );
}

#[test]
fn owned_wrappers_support_value_semantics_and_extraction() {
    assert_copy::<NotSensitiveDebug<Distinct>>();
    assert_copy::<NotSensitiveDisplay<Distinct>>();

    let debug = NotSensitiveDebug(Distinct::default());
    let display = NotSensitiveDisplay(Distinct::default());
    assert_eq!(debug, NotSensitiveDebug(Distinct(0)));
    assert_eq!(display, NotSensitiveDisplay(Distinct(0)));
    assert_eq!(
        NotSensitiveDebug(String::from("debug")).clone(),
        NotSensitiveDebug(String::from("debug"))
    );
    assert_eq!(
        NotSensitiveDisplay(String::from("display")).clone(),
        NotSensitiveDisplay(String::from("display"))
    );
    assert_eq!(debug.inner(), &Distinct(0));
    assert_eq!(display.inner(), &Distinct(0));
    assert_eq!(debug.into_inner(), Distinct(0));
    assert_eq!(display.into_inner(), Distinct(0));

    assert!(NotSensitiveDebug(Distinct(1)) < NotSensitiveDebug(Distinct(2)));
    assert!(NotSensitiveDisplay(Distinct(1)) < NotSensitiveDisplay(Distinct(2)));

    let mut left = DefaultHasher::new();
    NotSensitiveDebug(Distinct(9)).hash(&mut left);
    let mut right = DefaultHasher::new();
    NotSensitiveDebug(Distinct(9)).hash(&mut right);
    assert_eq!(left.finish(), right.finish());

    let mut left = DefaultHasher::new();
    NotSensitiveDisplay(Distinct(9)).hash(&mut left);
    let mut right = DefaultHasher::new();
    NotSensitiveDisplay(Distinct(9)).hash(&mut right);
    assert_eq!(left.finish(), right.finish());
}

#[test]
fn wrapper_storage_and_access_do_not_require_formatter_traits() {
    struct NoTraits(u8);

    let debug = NotSensitiveDebug(NoTraits(1));
    let display = NotSensitiveDisplay(NoTraits(2));
    assert_eq!(debug.inner().0, 1);
    assert_eq!(display.inner().0, 2);
    assert_eq!(debug.into_inner().0, 1);
    assert_eq!(display.into_inner().0, 2);
}

#[test]
fn extension_traits_keep_constructing_borrowed_format_wrappers() {
    let value = Distinct(3);

    assert_eq!(value.not_sensitive_debug().inner(), &&value);
    assert_eq!(value.not_sensitive_display().inner(), &&value);
}

#[test]
fn standard_library_values_work_in_owned_wrappers() {
    let debug = NotSensitiveDebug(Some(12_u8));
    let display = NotSensitiveDisplay(std::num::NonZeroU8::new(12).expect("non-zero fixture"));

    assert_eq!(
        debug.to_redacted_output(),
        RedactedOutput::Text("Some(12)".to_owned())
    );
    assert_eq!(
        display.to_redacted_output(),
        RedactedOutput::Text("12".to_owned())
    );
}

#[cfg(feature = "json")]
mod serde_contract {
    use redactable::{
        NotSensitiveDebug, NotSensitiveDisplay, RedactedOutput, Secret, SensitiveValue,
        ToRedactedOutput,
    };
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, PartialEq, Serialize)]
    struct PublicRecord {
        id: u64,
        label: String,
    }

    #[test]
    fn primitive_wrappers_round_trip_as_the_raw_inner_value() {
        let debug = NotSensitiveDebug(42_u64);
        let display = NotSensitiveDisplay(42_u64);

        assert_eq!(serde_json::to_value(debug).unwrap(), serde_json::json!(42));
        assert_eq!(
            serde_json::to_value(display).unwrap(),
            serde_json::json!(42)
        );
        assert_eq!(
            serde_json::from_value::<NotSensitiveDebug<u64>>(serde_json::json!(42))
                .unwrap()
                .into_inner(),
            42
        );
        assert_eq!(
            serde_json::from_value::<NotSensitiveDisplay<u64>>(serde_json::json!(42))
                .unwrap()
                .into_inner(),
            42
        );
    }

    #[test]
    fn structured_wrappers_round_trip_without_a_wrapper_object() {
        let expected = serde_json::json!({"id": 7, "label": "public"});
        let wrapped = NotSensitiveDebug(PublicRecord {
            id: 7,
            label: "public".to_owned(),
        });

        assert_eq!(serde_json::to_value(&wrapped).unwrap(), expected);
        let decoded: NotSensitiveDebug<PublicRecord> = serde_json::from_value(expected).unwrap();
        assert_eq!(
            decoded.into_inner(),
            PublicRecord {
                id: 7,
                label: "public".to_owned()
            }
        );

        let wrapped = NotSensitiveDisplay(PublicRecord {
            id: 8,
            label: "also-public".to_owned(),
        });
        let expected = serde_json::json!({"id": 8, "label": "also-public"});
        assert_eq!(serde_json::to_value(&wrapped).unwrap(), expected);
        let decoded: NotSensitiveDisplay<PublicRecord> = serde_json::from_value(expected).unwrap();
        assert_eq!(
            decoded.into_inner(),
            PublicRecord {
                id: 8,
                label: "also-public".to_owned()
            }
        );
    }

    #[test]
    fn raw_transport_and_logging_output_remain_distinct() {
        let public = NotSensitiveDebug("public");
        assert_eq!(
            serde_json::to_value(public).unwrap(),
            serde_json::json!("public")
        );
        assert_eq!(
            public.to_redacted_output(),
            RedactedOutput::Text("\"public\"".to_owned())
        );

        let sensitive = SensitiveValue::<String, Secret>::from("secret".to_owned());
        assert_eq!(
            serde_json::to_value(&sensitive).unwrap(),
            serde_json::json!("secret")
        );
        assert_eq!(
            sensitive.to_redacted_output(),
            RedactedOutput::Text("[REDACTED]".to_owned())
        );

        let nested = NotSensitiveDebug(sensitive);
        let RedactedOutput::Text(nested_output) = nested.to_redacted_output() else {
            panic!("debug output must remain textual");
        };
        assert!(nested_output.contains("[REDACTED]"));
        assert!(!nested_output.contains("secret"));
    }
}
