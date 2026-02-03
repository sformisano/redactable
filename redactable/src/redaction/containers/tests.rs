//! Tests for standard container redaction behavior.

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    rc::Rc,
    sync::Arc,
};

use crate::{Default, Sensitive, redaction::traits::Redactable};

#[derive(Clone, Sensitive)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
struct SensitiveString {
    #[sensitive(Default)]
    value: String,
}

#[test]
fn passthrough_string_unchanged() {
    let s = "hello".to_string();
    let redacted = s.clone().redact();
    assert_eq!(redacted, s);
}

#[test]
fn passthrough_integers_unchanged() {
    assert_eq!(0i32.redact(), 0i32);
    assert_eq!(42u64.redact(), 42u64);
    assert_eq!((-1i8).redact(), -1i8);
}

#[test]
fn option_traversal_redacts_inner() {
    let value = Some(SensitiveString {
        value: "secret".to_string(),
    });
    let redacted = value.redact();
    assert_eq!(redacted.unwrap().value, "[REDACTED]");
}

#[test]
fn option_none_unchanged() {
    let o: Option<String> = None;
    let redacted = o.redact();
    assert!(redacted.is_none());
}

#[test]
fn result_traversal_redacts_ok_and_err() {
    let ok_value: Result<SensitiveString, SensitiveString> = Ok(SensitiveString {
        value: "ok_secret".to_string(),
    });
    let redacted_ok = ok_value.redact().unwrap();
    assert_eq!(redacted_ok.value, "[REDACTED]");

    let err_value: Result<SensitiveString, SensitiveString> = Err(SensitiveString {
        value: "err_secret".to_string(),
    });
    let redacted_err = err_value.redact().unwrap_err();
    assert_eq!(redacted_err.value, "[REDACTED]");
}

#[test]
fn vec_traversal_redacts_all_elements() {
    let values = vec![
        SensitiveString {
            value: "first".to_string(),
        },
        SensitiveString {
            value: "second".to_string(),
        },
    ];
    let redacted = values.redact();
    assert!(
        redacted
            .into_iter()
            .all(|value| value.value == "[REDACTED]")
    );
}

#[test]
fn box_traversal_redacts_inner() {
    let b = Box::new(SensitiveString {
        value: "secret".to_string(),
    });
    let redacted = b.redact();
    assert_eq!(redacted.value, "[REDACTED]");
}

#[test]
fn arc_traversal_redacts_inner() {
    let a = Arc::new(SensitiveString {
        value: "secret".to_string(),
    });
    let redacted = a.redact();
    assert_eq!(redacted.value, "[REDACTED]");
}

#[test]
fn rc_traversal_redacts_inner() {
    let r = Rc::new(SensitiveString {
        value: "secret".to_string(),
    });
    let redacted = r.redact();
    assert_eq!(redacted.value, "[REDACTED]");
}

#[test]
fn map_traversal_redacts_values() {
    let mut map: HashMap<String, SensitiveString> = HashMap::new();
    map.insert(
        "key".to_string(),
        SensitiveString {
            value: "secret".to_string(),
        },
    );
    let redacted = map.redact();
    assert_eq!(redacted["key"].value, "[REDACTED]");
}

#[test]
fn btreemap_traversal_redacts_values() {
    let mut map: BTreeMap<String, SensitiveString> = BTreeMap::new();
    map.insert(
        "key".to_string(),
        SensitiveString {
            value: "secret".to_string(),
        },
    );
    let redacted = map.redact();
    assert_eq!(redacted["key"].value, "[REDACTED]");
}

#[test]
fn map_keys_are_not_redacted_by_default() {
    let mut map: HashMap<String, SensitiveString> = HashMap::new();
    map.insert(
        "public_key".to_string(),
        SensitiveString {
            value: "secret".to_string(),
        },
    );
    let redacted = map.redact();
    assert!(redacted.contains_key("public_key"));
    assert_eq!(redacted["public_key"].value, "[REDACTED]");
}

#[test]
fn map_keys_are_never_redacted() {
    #[derive(Clone, Hash, Eq, PartialEq, Sensitive)]
    #[cfg_attr(feature = "json", derive(serde::Serialize))]
    struct SensitiveKey {
        #[sensitive(Default)]
        value: String,
    }

    let mut map: HashMap<SensitiveKey, SensitiveString> = HashMap::new();
    let key = SensitiveKey {
        value: "key_secret".to_string(),
    };
    map.insert(
        key.clone(),
        SensitiveString {
            value: "secret".to_string(),
        },
    );

    let redacted = map.redact();
    assert!(redacted.contains_key(&key));
    assert_eq!(redacted[&key].value, "[REDACTED]");
}

#[test]
fn btreeset_traversal_keeps_elements() {
    let mut set: BTreeSet<String> = BTreeSet::new();
    set.insert("public".to_string());
    let redacted = set.redact();
    assert!(redacted.contains("public"));
}

#[test]
fn hashset_traversal_keeps_elements() {
    let mut set: HashSet<String> = HashSet::new();
    set.insert("public".to_string());
    let redacted = set.redact();
    assert!(redacted.contains("public"));
}

#[test]
fn nested_container_traversal_redacts_inner() {
    let values = vec![Some(SensitiveString {
        value: "secret".to_string(),
    })];
    let redacted = values.redact();
    assert_eq!(redacted[0].as_ref().unwrap().value, "[REDACTED]");
}

#[test]
fn refcell_traversal_redacts_inner() {
    let r = RefCell::new(SensitiveString {
        value: "secret".to_string(),
    });
    let redacted = r.redact();
    assert_eq!(redacted.borrow().value, "[REDACTED]");
}

#[test]
fn cell_passthrough_unchanged() {
    let c = Cell::new(42u32);
    let redacted = c.redact();
    assert_eq!(redacted.get(), 42);
}

#[cfg(feature = "ip-address")]
#[test]
fn ipaddr_redacts_by_default() {
    use std::net::IpAddr;

    let ip: IpAddr = "192.168.1.100".parse().expect("valid IPv4");
    let redacted = ip.redact();

    assert_eq!(redacted, "0.0.0.100".parse::<IpAddr>().unwrap());
}

#[cfg(feature = "ip-address")]
#[test]
fn socketaddr_redacts_ip_only() {
    use std::net::SocketAddr;

    let addr: SocketAddr = "10.1.2.3:443".parse().expect("valid socket addr");
    let redacted = addr.redact();

    assert_eq!(redacted, "0.0.0.3:443".parse::<SocketAddr>().unwrap());
}
