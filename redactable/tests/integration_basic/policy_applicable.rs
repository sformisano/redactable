use super::*;

#[test]
fn applies_policy_to_option_vec() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct NestedWrappers {
        #[sensitive(Secret)]
        addresses: Option<Vec<String>>,
    }

    let n = NestedWrappers {
        addresses: Some(vec!["123 Main St".into(), "456 Oak Ave".into()]),
    };
    let redacted = n.redact();

    let addrs = redacted.addresses.unwrap();
    assert_eq!(addrs[0], "[REDACTED]");
    assert_eq!(addrs[1], "[REDACTED]");
}

#[test]
fn applies_policy_to_vec_option() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct NestedWrappers {
        #[sensitive(Secret)]
        values: Vec<Option<String>>,
    }

    let n = NestedWrappers {
        values: vec![Some("secret1".into()), None, Some("secret2".into())],
    };
    let redacted = n.redact();

    assert_eq!(redacted.values[0], Some("[REDACTED]".into()));
    assert_eq!(redacted.values[1], None);
    assert_eq!(redacted.values[2], Some("[REDACTED]".into()));
}

#[test]
fn applies_policy_to_deeply_nested_containers() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct DeepNest {
        #[sensitive(Secret)]
        values: Option<Vec<Option<String>>>,
    }

    let n = DeepNest {
        values: Some(vec![Some("secret".into()), None]),
    };
    let redacted = n.redact();

    let values = redacted.values.unwrap();
    assert_eq!(values[0], Some("[REDACTED]".into()));
    assert_eq!(values[1], None);
}

#[test]
fn applies_policy_to_hashmap_vec() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct MapWithVec {
        #[sensitive(Secret)]
        data: HashMap<String, Vec<String>>,
    }

    let mut data = HashMap::new();
    data.insert("secrets".into(), vec!["secret1".into(), "secret2".into()]);

    let n = MapWithVec { data };
    let redacted = n.redact();

    assert_eq!(
        redacted.data.get("secrets"),
        Some(&vec!["[REDACTED]".to_string(), "[REDACTED]".to_string()])
    );
}
