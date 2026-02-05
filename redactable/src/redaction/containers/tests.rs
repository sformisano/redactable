//! Tests for standard container redaction behavior.

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    rc::Rc,
    sync::Arc,
};

use crate::{Secret, Sensitive, redaction::traits::Redactable};

#[derive(Clone, Sensitive)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
struct SensitiveString {
    #[sensitive(Secret)]
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
fn passthrough_nonzero_integers_unchanged() {
    use std::num::{NonZeroI32, NonZeroU64};

    let signed = NonZeroI32::new(42).unwrap();
    let unsigned = NonZeroU64::new(100).unwrap();

    assert_eq!(signed.redact(), signed);
    assert_eq!(unsigned.redact(), unsigned);
}

#[test]
fn passthrough_duration_unchanged() {
    use std::time::Duration;

    let duration = Duration::from_secs(60);
    assert_eq!(duration.redact(), duration);
}

#[test]
fn passthrough_instant_unchanged() {
    use std::time::Instant;

    let instant = Instant::now();
    assert_eq!(instant.redact(), instant);
}

#[test]
fn passthrough_system_time_unchanged() {
    use std::time::SystemTime;

    let system_time = SystemTime::now();
    assert_eq!(system_time.redact(), system_time);
}

#[test]
fn passthrough_ordering_unchanged() {
    use std::cmp::Ordering;

    assert_eq!(Ordering::Less.redact(), Ordering::Less);
    assert_eq!(Ordering::Equal.redact(), Ordering::Equal);
    assert_eq!(Ordering::Greater.redact(), Ordering::Greater);
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
        #[sensitive(Secret)]
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

// =============================================================================
// chrono passthrough tests
// =============================================================================

#[cfg(feature = "chrono")]
#[test]
fn passthrough_chrono_duration_unchanged() {
    use chrono::Duration;

    let duration = Duration::seconds(3600);
    assert_eq!(duration.redact(), duration);
}

#[cfg(feature = "chrono")]
#[test]
fn passthrough_chrono_month_unchanged() {
    use chrono::Month;

    assert_eq!(Month::January.redact(), Month::January);
    assert_eq!(Month::December.redact(), Month::December);
}

#[cfg(feature = "chrono")]
#[test]
fn passthrough_chrono_weekday_unchanged() {
    use chrono::Weekday;

    assert_eq!(Weekday::Mon.redact(), Weekday::Mon);
    assert_eq!(Weekday::Sun.redact(), Weekday::Sun);
}

// =============================================================================
// time crate passthrough tests
// =============================================================================

#[cfg(feature = "time")]
#[test]
fn passthrough_time_duration_unchanged() {
    use time::Duration;

    let duration = Duration::hours(2);
    assert_eq!(duration.redact(), duration);
}

#[cfg(feature = "time")]
#[test]
fn passthrough_time_utc_offset_unchanged() {
    use time::UtcOffset;

    let offset = UtcOffset::from_hms(5, 30, 0).unwrap();
    assert_eq!(offset.redact(), offset);
}

#[cfg(feature = "time")]
#[test]
fn passthrough_time_month_unchanged() {
    use time::Month;

    assert_eq!(Month::January.redact(), Month::January);
    assert_eq!(Month::December.redact(), Month::December);
}

#[cfg(feature = "time")]
#[test]
fn passthrough_time_weekday_unchanged() {
    use time::Weekday;

    assert_eq!(Weekday::Monday.redact(), Weekday::Monday);
    assert_eq!(Weekday::Sunday.redact(), Weekday::Sunday);
}
