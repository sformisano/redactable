use super::*;

#[test]
fn traverses_btreemap_values() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct SensitiveValue2 {
        #[sensitive(Secret)]
        value: String,
    }

    let mut map: BTreeMap<String, SensitiveValue2> = BTreeMap::new();
    map.insert(
        "key".to_string(),
        SensitiveValue2 {
            value: "value".to_string(),
        },
    );
    let redacted = map.redact();
    assert_eq!(redacted.get("key").unwrap().value, "[REDACTED]");
}

#[test]
fn traverses_box_contents() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct BoxedSensitive {
        #[sensitive(Secret)]
        value: String,
    }

    let boxed: Box<BoxedSensitive> = Box::new(BoxedSensitive {
        value: "secret_in_box".into(),
    });
    let redacted = boxed.redact();

    assert_eq!(redacted.value, "[REDACTED]");
}

#[test]
fn traverses_nested_boxes() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct DeepSensitive {
        #[sensitive(Secret)]
        value: String,
    }

    let nested: Box<Box<DeepSensitive>> = Box::new(Box::new(DeepSensitive {
        value: "deeply_nested".into(),
    }));
    let redacted = nested.redact();

    assert_eq!(redacted.value, "[REDACTED]");
}

#[test]
fn traverses_generic_containers() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct SensitiveWrapper {
        #[sensitive(Secret)]
        value: String,
    }

    let vec_data = vec![
        SensitiveWrapper {
            value: "secret1".into(),
        },
        SensitiveWrapper {
            value: "secret2".into(),
        },
    ];
    let redacted = vec_data.redact();
    assert_eq!(redacted[0].value, "[REDACTED]");
    assert_eq!(redacted[1].value, "[REDACTED]");

    let opt_data = Some(SensitiveWrapper {
        value: "secret".into(),
    });
    let redacted = opt_data.redact();
    assert_eq!(redacted.unwrap().value, "[REDACTED]");

    let mut map_data: HashMap<String, SensitiveWrapper> = HashMap::new();
    map_data.insert(
        "key".into(),
        SensitiveWrapper {
            value: "secret".into(),
        },
    );
    let redacted = map_data.redact();
    assert_eq!(redacted["key"].value, "[REDACTED]");
}

#[test]
fn traverses_option_vec_nesting() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct SensitiveItem {
        #[sensitive(Secret)]
        value: String,
    }

    let data: Option<Vec<SensitiveItem>> = Some(vec![
        SensitiveItem {
            value: "first".into(),
        },
        SensitiveItem {
            value: "second".into(),
        },
    ]);

    let redacted = data.redact();

    let items = redacted.unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].value, "[REDACTED]");
    assert_eq!(items[1].value, "[REDACTED]");
}
