use std::collections::{BTreeMap, HashMap};

use serde::{Serialize, Serializer, ser::Error};
use serde_json::json;

use crate::{
    BypassDebugRedaction, BypassDisplayRedaction, BypassJsonRedaction, NotSensitive, Redactable,
    Secret, Sensitive, SensitiveDisplay, SensitiveDual, ToRedacted,
};

const SECRET_KEY: &str = "PRIVATE-ACCOUNT-4901";
const SECRET_VALUE: &str = "PRIVATE-TOKEN-1902";

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Sensitive)]
struct AccountKey(#[sensitive(Secret)] String);

#[derive(Clone, Serialize, Sensitive)]
struct Entry {
    #[sensitive(Secret)]
    token: String,
}

fn entry() -> Entry {
    Entry {
        token: SECRET_VALUE.into(),
    }
}

fn output_key() -> &'static str {
    if cfg!(feature = "mask-map-keys") {
        "[REDACTED-KEY-0]"
    } else {
        SECRET_KEY
    }
}

#[test]
fn sensitive_map_output_obeys_feature_without_changing_transport_or_traversal() {
    #[derive(Clone, Serialize, Sensitive)]
    struct Input {
        accounts: HashMap<AccountKey, Entry>,
    }
    let input = Input {
        accounts: HashMap::from([(AccountKey(SECRET_KEY.into()), entry())]),
    };
    let produced = input.to_redacted();
    assert_eq!(
        produced.json(),
        json!({"accounts": {output_key(): {"token": "[REDACTED]"}}})
    );
    assert!(!produced.text().contains(SECRET_VALUE));
    assert_eq!(
        produced.text().contains(SECRET_KEY),
        !cfg!(feature = "mask-map-keys")
    );
    assert_eq!(
        serde_json::to_value(&input).unwrap(),
        json!({"accounts": {SECRET_KEY: {"token": SECRET_VALUE}}})
    );
    assert_eq!(
        serde_json::to_value(input.redact()).unwrap(),
        json!({"accounts": {SECRET_KEY: {"token": "[REDACTED]"}}})
    );
}

#[test]
fn nested_map_output_preserves_struct_and_variant_names() {
    #[derive(Clone, Serialize, Sensitive)]
    struct Newtype(BTreeMap<String, Entry>);
    #[derive(Clone, Serialize, Sensitive)]
    enum Shape {
        Newtype(Newtype),
        Tuple(Newtype, Newtype),
        Named { records: Newtype },
    }
    #[derive(Clone, Serialize, Sensitive)]
    struct Input {
        rows: Option<Vec<Shape>>,
    }
    let map = || {
        Newtype(BTreeMap::from([
            (SECRET_KEY.into(), entry()),
            ("PRIVATE-ACCOUNT-4902".into(), entry()),
        ]))
    };
    let input = Input {
        rows: Some(vec![
            Shape::Newtype(map()),
            Shape::Tuple(map(), map()),
            Shape::Named { records: map() },
        ]),
    };
    let expected_map = if cfg!(feature = "mask-map-keys") {
        json!({
            "[REDACTED-KEY-0]": {"token": "[REDACTED]"},
            "[REDACTED-KEY-1]": {"token": "[REDACTED]"}
        })
    } else {
        json!({
            SECRET_KEY: {"token": "[REDACTED]"},
            "PRIVATE-ACCOUNT-4902": {"token": "[REDACTED]"}
        })
    };
    assert_eq!(
        input.to_redacted().json(),
        json!({"rows": [
            {"Newtype": expected_map},
            {"Tuple": [expected_map, expected_map]},
            {"Named": {"records": expected_map}}
        ]})
    );
}

#[test]
fn flattened_fields_and_internally_tagged_maps_follow_serde_map_shape() {
    #[derive(Clone, Serialize, Sensitive)]
    struct Flattened {
        #[not_sensitive]
        label: String,
        #[serde(flatten)]
        entry: Entry,
    }
    #[derive(Clone, Serialize, Sensitive)]
    #[serde(tag = "kind")]
    enum Tagged {
        Map(BTreeMap<String, Entry>),
        Named { entry: Entry },
    }
    let flattened = Flattened {
        label: "summary".into(),
        entry: entry(),
    };
    let expected_flattened = if cfg!(feature = "mask-map-keys") {
        json!({"[REDACTED-KEY-0]": "summary", "[REDACTED-KEY-1]": "[REDACTED]"})
    } else {
        json!({"label": "summary", "token": "[REDACTED]"})
    };
    assert_eq!(flattened.to_redacted().json(), expected_flattened);

    let map = Tagged::Map(BTreeMap::from([(SECRET_KEY.into(), entry())]));
    let expected_map = if cfg!(feature = "mask-map-keys") {
        json!({
            "[REDACTED-KEY-0]": "Map",
            "[REDACTED-KEY-1]": {"token": "[REDACTED]"}
        })
    } else {
        json!({"kind": "Map", SECRET_KEY: {"token": "[REDACTED]"}})
    };
    assert_eq!(map.to_redacted().json(), expected_map);
    assert_eq!(
        Tagged::Named { entry: entry() }.to_redacted().json(),
        json!({"kind": "Named", "entry": {"token": "[REDACTED]"}})
    );
}

#[test]
fn public_producers_and_bypasses_keep_their_disclosure_contract() {
    #[derive(Serialize, NotSensitive)]
    struct PublicInput {
        records: BTreeMap<String, u64>,
    }
    #[derive(Clone, Serialize, Sensitive)]
    struct SensitiveInput {
        #[not_sensitive]
        records: BTreeMap<String, u64>,
        bypass: crate::BypassRedaction<BTreeMap<String, u64>>,
    }
    let public = PublicInput {
        records: BTreeMap::from([(SECRET_KEY.into(), 7)]),
    };
    let raw = json!({"records": {SECRET_KEY: 7}});
    assert_eq!(public.to_redacted().json(), raw);
    assert_eq!(BypassJsonRedaction(&public).to_redacted().json(), raw);
    assert_eq!(
        BypassDisplayRedaction(SECRET_KEY).to_redacted().text(),
        SECRET_KEY
    );
    assert_eq!(
        BypassDebugRedaction(SECRET_KEY).to_redacted().text(),
        format!("{SECRET_KEY:?}")
    );

    let sensitive = SensitiveInput {
        bypass: crate::BypassRedaction(public.records.clone()),
        records: public.records,
    };
    assert_eq!(
        sensitive.to_redacted().json(),
        json!({"records": {output_key(): 7}, "bypass": {output_key(): 7}})
    );
    assert_eq!(
        BypassJsonRedaction(&sensitive).to_redacted().json(),
        json!({"records": {SECRET_KEY: 7}, "bypass": {SECRET_KEY: 7}})
    );
}

#[test]
fn display_only_producer_remains_borrowed_and_text_shaped() {
    #[derive(SensitiveDisplay)]
    #[error("token={token}")]
    struct TextOnly {
        #[sensitive(Secret)]
        token: String,
    }
    let source = TextOnly {
        token: SECRET_VALUE.into(),
    };
    let produced = source.to_redacted();
    assert_eq!(produced.text(), "token=[REDACTED]");
    assert_eq!(produced.json(), json!({"message": "token=[REDACTED]"}));
    assert_eq!(source.token, SECRET_VALUE);
}

#[test]
fn dual_producer_and_precomputed_output_keep_one_time_work_and_distinct_formats() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use crate::{RedactionPolicy, TextPolicyKind, TextRedactionPolicy};

    static POLICIES: AtomicUsize = AtomicUsize::new(0);
    struct CountedPolicy;
    impl RedactionPolicy for CountedPolicy {
        type Kind = TextPolicyKind;
        fn policy() -> TextRedactionPolicy {
            POLICIES.fetch_add(1, Ordering::SeqCst);
            TextRedactionPolicy::default_full()
        }
    }
    #[derive(Serialize, SensitiveDual)]
    #[error("token={token}")]
    struct Input {
        #[sensitive(CountedPolicy)]
        token: String,
        accounts: HashMap<AccountKey, Entry>,
        #[not_sensitive]
        #[serde(skip)]
        clones: Arc<AtomicUsize>,
    }
    impl Clone for Input {
        fn clone(&self) -> Self {
            self.clones.fetch_add(1, Ordering::SeqCst);
            Self {
                token: self.token.clone(),
                accounts: self.accounts.clone(),
                clones: self.clones.clone(),
            }
        }
    }
    let source = Input {
        token: SECRET_VALUE.into(),
        accounts: HashMap::from([(AccountKey(SECRET_KEY.into()), entry())]),
        clones: Arc::new(AtomicUsize::new(0)),
    };
    let produced = source.to_redacted();
    let expected = json!({
        "token": "[REDACTED]",
        "accounts": {output_key(): {"token": "[REDACTED]"}}
    });
    for _ in 0..3 {
        assert_eq!(produced.text(), "token=[REDACTED]");
        assert_eq!(produced.json(), expected);
        assert_eq!(produced.to_redacted(), produced);
    }
    assert_eq!(source.clones.load(Ordering::SeqCst), 1);
    assert_eq!(POLICIES.load(Ordering::SeqCst), 2);
    assert_eq!(source.token, SECRET_VALUE);
}

#[test]
fn serialization_failure_replaces_the_whole_json_and_preserves_dual_text() {
    #[derive(Clone, SensitiveDual)]
    #[error("token={token}")]
    struct Input {
        #[sensitive(Secret)]
        token: String,
    }
    impl Serialize for Input {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeMap;
            let mut map = serializer.serialize_map(Some(1))?;
            map.serialize_entry(SECRET_KEY, &self.token)?;
            Err(S::Error::custom(SECRET_VALUE))
        }
    }
    let produced = Input {
        token: SECRET_VALUE.into(),
    }
    .to_redacted();
    assert_eq!(produced.json(), json!("[REDACTED]"));
    assert_eq!(produced.text(), "token=[REDACTED]");
    assert!(!format!("{produced:?}").contains(SECRET_KEY));
    assert!(!format!("{produced:?}").contains(SECRET_VALUE));
}
