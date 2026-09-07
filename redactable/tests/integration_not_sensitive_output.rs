//! Behavior and transport contracts for the owned members of the Bypass family.

use std::{
    collections::hash_map::DefaultHasher,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    num::NonZeroU8,
};

use redactable::{BypassDebugRedaction, BypassDisplayRedaction, RedactedValue, ToRedacted};

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Distinct(u8);

impl Debug for Distinct {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "debug:{}", self.0)
    }
}

impl Display for Distinct {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "display:{}", self.0)
    }
}

fn assert_copy<T: Copy>() {}

fn output<T: ToRedacted>(value: &T) -> RedactedValue {
    value.to_redacted()
}

#[test]
fn owned_wrappers_preserve_the_selected_format() {
    let debug = BypassDebugRedaction(Distinct(7));
    let display = BypassDisplayRedaction(Distinct(7));

    assert_eq!(output(&debug).text(), "debug:7");
    assert_eq!(output(&display).text(), "display:7");
}

#[test]
fn owned_wrappers_support_value_semantics_and_extraction() {
    assert_copy::<BypassDebugRedaction<Distinct>>();
    assert_copy::<BypassDisplayRedaction<Distinct>>();

    let debug = BypassDebugRedaction(Distinct::default());
    let display = BypassDisplayRedaction(Distinct::default());
    assert_eq!(debug, BypassDebugRedaction(Distinct(0)));
    assert_eq!(display, BypassDisplayRedaction(Distinct(0)));
    assert_eq!(
        BypassDebugRedaction(String::from("debug")).clone(),
        BypassDebugRedaction(String::from("debug"))
    );
    assert_eq!(
        BypassDisplayRedaction(String::from("display")).clone(),
        BypassDisplayRedaction(String::from("display"))
    );
    assert_eq!(debug.inner(), &Distinct(0));
    assert_eq!(display.inner(), &Distinct(0));
    assert_eq!(debug.into_inner(), Distinct(0));
    assert_eq!(display.into_inner(), Distinct(0));

    assert!(BypassDebugRedaction(Distinct(1)) < BypassDebugRedaction(Distinct(2)));
    assert!(BypassDisplayRedaction(Distinct(1)) < BypassDisplayRedaction(Distinct(2)));

    let mut left = DefaultHasher::new();
    BypassDebugRedaction(Distinct(9)).hash(&mut left);
    let mut right = DefaultHasher::new();
    BypassDebugRedaction(Distinct(9)).hash(&mut right);
    assert_eq!(left.finish(), right.finish());

    let mut left = DefaultHasher::new();
    BypassDisplayRedaction(Distinct(9)).hash(&mut left);
    let mut right = DefaultHasher::new();
    BypassDisplayRedaction(Distinct(9)).hash(&mut right);
    assert_eq!(left.finish(), right.finish());
}

#[test]
fn wrapper_storage_and_access_do_not_require_formatter_traits() {
    struct NoTraits(u8);

    let debug = BypassDebugRedaction(NoTraits(1));
    let display = BypassDisplayRedaction(NoTraits(2));
    assert_eq!(debug.inner().0, 1);
    assert_eq!(display.inner().0, 2);
    assert_eq!(debug.into_inner().0, 1);
    assert_eq!(display.into_inner().0, 2);
}

#[test]
fn tuple_construction_over_a_reference_replaces_the_extension_traits() {
    let value = Distinct(3);

    assert_eq!(BypassDebugRedaction(&value).inner(), &&value);
    assert_eq!(BypassDisplayRedaction(&value).inner(), &&value);
}

#[test]
fn standard_library_values_work_in_owned_wrappers() {
    let debug = BypassDebugRedaction(Some(12_u8));
    let display = BypassDisplayRedaction(NonZeroU8::new(12).expect("non-zero fixture"));

    assert_eq!(debug.to_redacted().text(), "Some(12)");
    assert_eq!(display.to_redacted().text(), "12");
}

mod serde_contract {
    use redactable::{
        BypassDebugRedaction, BypassDisplayRedaction, Secret, SensitiveValue, ToRedacted,
    };
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, PartialEq, Serialize)]
    struct PublicRecord {
        id: u64,
        label: String,
    }

    #[test]
    fn primitive_wrappers_round_trip_as_the_raw_inner_value() {
        let debug = BypassDebugRedaction(42_u64);
        let display = BypassDisplayRedaction(42_u64);

        assert_eq!(serde_json::to_value(debug).unwrap(), serde_json::json!(42));
        assert_eq!(
            serde_json::to_value(display).unwrap(),
            serde_json::json!(42)
        );
        assert_eq!(
            serde_json::from_value::<BypassDebugRedaction<u64>>(serde_json::json!(42))
                .unwrap()
                .into_inner(),
            42
        );
        assert_eq!(
            serde_json::from_value::<BypassDisplayRedaction<u64>>(serde_json::json!(42))
                .unwrap()
                .into_inner(),
            42
        );
    }

    #[test]
    fn structured_wrappers_round_trip_without_a_wrapper_object() {
        let expected = serde_json::json!({"id": 7, "label": "public"});
        let wrapped = BypassDebugRedaction(PublicRecord {
            id: 7,
            label: "public".to_owned(),
        });

        assert_eq!(serde_json::to_value(&wrapped).unwrap(), expected);
        let decoded: BypassDebugRedaction<PublicRecord> = serde_json::from_value(expected).unwrap();
        assert_eq!(
            decoded.into_inner(),
            PublicRecord {
                id: 7,
                label: "public".to_owned()
            }
        );

        let wrapped = BypassDisplayRedaction(PublicRecord {
            id: 8,
            label: "also-public".to_owned(),
        });
        let expected = serde_json::json!({"id": 8, "label": "also-public"});
        assert_eq!(serde_json::to_value(&wrapped).unwrap(), expected);
        let decoded: BypassDisplayRedaction<PublicRecord> =
            serde_json::from_value(expected).unwrap();
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
        let public = BypassDebugRedaction("public");
        assert_eq!(
            serde_json::to_value(public).unwrap(),
            serde_json::json!("public")
        );
        assert_eq!(public.to_redacted().text(), "\"public\"");

        let sensitive = SensitiveValue::<String, Secret>::from("secret".to_owned());
        assert_eq!(
            serde_json::to_value(&sensitive).unwrap(),
            serde_json::json!("secret")
        );
        assert_eq!(sensitive.to_redacted().text(), "[REDACTED]");

        let nested = BypassDebugRedaction(sensitive);
        let nested_output = nested.to_redacted();
        let nested_output = nested_output.text();
        assert!(nested_output.contains("[REDACTED]"));
        assert!(!nested_output.contains("secret"));
    }
}
