//! Tests for standard container redaction behavior.

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    rc::Rc,
    sync::Arc,
};

use crate::{Secret, Sensitive, redaction::traits::Redactable};

/// Runs the traversal machinery on a value regardless of certification.
///
/// Leaf passthroughs deliberately do not implement `Redactable` (no declared
/// redaction behavior), but their machinery-level passthrough is still a
/// contract worth asserting.
fn machine_redact<T: crate::redaction::traits::RedactableWithMapper>(value: T) -> T {
    crate::redaction::redact::redact(value)
}

#[derive(Clone, Sensitive)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
struct SensitiveString {
    #[sensitive(Secret)]
    value: String,
}

#[test]
fn passthrough_string_unchanged() {
    let s = "hello".to_string();
    let redacted = machine_redact(s.clone());
    assert_eq!(redacted, s);
}

#[test]
fn passthrough_integers_unchanged() {
    assert_eq!(machine_redact(0i32), 0i32);
    assert_eq!(machine_redact(42u64), 42u64);
    assert_eq!(machine_redact(-1i8), -1i8);
}

#[test]
fn passthrough_nonzero_integers_unchanged() {
    use std::num::{NonZeroI32, NonZeroU64};

    let signed = NonZeroI32::new(42).unwrap();
    let unsigned = NonZeroU64::new(100).unwrap();

    assert_eq!(machine_redact(signed), signed);
    assert_eq!(machine_redact(unsigned), unsigned);
}

#[test]
fn passthrough_duration_unchanged() {
    use std::time::Duration;

    let duration = Duration::from_mins(1);
    assert_eq!(machine_redact(duration), duration);
}

#[test]
fn passthrough_instant_unchanged() {
    use std::time::Instant;

    let instant = Instant::now();
    assert_eq!(machine_redact(instant), instant);
}

#[test]
fn passthrough_system_time_unchanged() {
    use std::time::SystemTime;

    let system_time = SystemTime::now();
    assert_eq!(machine_redact(system_time), system_time);
}

#[test]
fn passthrough_ordering_unchanged() {
    use std::cmp::Ordering;

    assert_eq!(machine_redact(Ordering::Less), Ordering::Less);
    assert_eq!(machine_redact(Ordering::Equal), Ordering::Equal);
    assert_eq!(machine_redact(Ordering::Greater), Ordering::Greater);
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
    let redacted = machine_redact(o);
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
    let redacted = machine_redact(set);
    assert!(redacted.contains("public"));
}

#[test]
fn hashset_traversal_keeps_elements() {
    let mut set: HashSet<String> = HashSet::new();
    set.insert("public".to_string());
    let redacted = machine_redact(set);
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
    let redacted = machine_redact(c);
    assert_eq!(redacted.get(), 42);
}

#[cfg(feature = "ip-address")]
#[test]
fn ipaddr_passthrough_unchanged() {
    use std::net::IpAddr;

    let ip: IpAddr = "192.168.1.100".parse().expect("valid IPv4");
    let redacted = machine_redact(ip);

    assert_eq!(redacted, ip);
}

#[cfg(feature = "ip-address")]
#[test]
fn socketaddr_passthrough_unchanged() {
    use std::net::SocketAddr;

    let addr: SocketAddr = "10.1.2.3:443".parse().expect("valid socket addr");
    let redacted = machine_redact(addr);

    assert_eq!(redacted, addr);
}

#[cfg(feature = "ip-address")]
#[test]
fn annotated_ipaddr_redacts() {
    use std::net::{IpAddr, SocketAddr};

    use crate::{IpAddress, RedactableWithFormatter, SensitiveDisplay};

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Connection {
        #[sensitive(IpAddress)]
        ip: IpAddr,
        #[sensitive(IpAddress)]
        socket: SocketAddr,
    }

    #[derive(SensitiveDisplay)]
    #[error("client {ip}")]
    struct DisplayConnection {
        #[sensitive(IpAddress)]
        ip: IpAddr,
    }

    let connection = Connection {
        ip: "192.168.1.100".parse().expect("valid IPv4"),
        socket: "10.1.2.3:443".parse().expect("valid socket addr"),
    };
    let redacted = connection.redact();

    assert_eq!(redacted.ip, "0.0.0.100".parse::<IpAddr>().unwrap());
    assert_eq!(
        redacted.socket,
        "0.0.0.3:443".parse::<SocketAddr>().unwrap()
    );

    let display_connection = DisplayConnection {
        ip: "192.168.1.100".parse().expect("valid IPv4"),
    };
    assert_eq!(
        display_connection.redacted_display().to_string(),
        "client 0.0.0.100"
    );
}

// =============================================================================
// chrono passthrough tests
// =============================================================================

#[cfg(feature = "chrono")]
#[test]
fn passthrough_chrono_duration_unchanged() {
    use chrono::Duration;

    let duration = Duration::seconds(3600);
    assert_eq!(machine_redact(duration), duration);
}

#[cfg(feature = "chrono")]
#[test]
fn passthrough_chrono_month_unchanged() {
    use chrono::Month;

    assert_eq!(machine_redact(Month::January), Month::January);
    assert_eq!(machine_redact(Month::December), Month::December);
}

#[cfg(feature = "chrono")]
#[test]
fn passthrough_chrono_weekday_unchanged() {
    use chrono::Weekday;

    assert_eq!(machine_redact(Weekday::Mon), Weekday::Mon);
    assert_eq!(machine_redact(Weekday::Sun), Weekday::Sun);
}

// =============================================================================
// time crate passthrough tests
// =============================================================================

#[cfg(feature = "time")]
#[test]
fn passthrough_time_duration_unchanged() {
    use time::Duration;

    let duration = Duration::hours(2);
    assert_eq!(machine_redact(duration), duration);
}

#[cfg(feature = "time")]
#[test]
fn passthrough_time_utc_offset_unchanged() {
    use time::UtcOffset;

    let offset = UtcOffset::from_hms(5, 30, 0).unwrap();
    assert_eq!(machine_redact(offset), offset);
}

#[cfg(feature = "time")]
#[test]
fn passthrough_time_month_unchanged() {
    use time::Month;

    assert_eq!(machine_redact(Month::January), Month::January);
    assert_eq!(machine_redact(Month::December), Month::December);
}

#[cfg(feature = "time")]
#[test]
fn passthrough_time_weekday_unchanged() {
    use time::Weekday;

    assert_eq!(machine_redact(Weekday::Monday), Weekday::Monday);
    assert_eq!(machine_redact(Weekday::Sunday), Weekday::Sunday);
}
