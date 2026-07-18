//! Runtime regressions for semantic policies, borrow conflicts, and macro hygiene.

#[cfg(feature = "ip-address")]
use std::net::{Ipv4Addr, SocketAddr};
use std::{
    borrow::Cow,
    cell::RefCell,
    collections::HashMap,
    net::IpAddr,
    panic::{AssertUnwindSafe, catch_unwind},
};

use redactable::{Redactable, RedactableWithFormatter, Secret, Sensitive, SensitiveDisplay};
use serde::Serialize;

const CANARY: &str = "phase02-refcell-canary-3d91";

#[derive(SensitiveDisplay)]
#[error("{value} | {value:?}")]
struct RefCellDisplay<T> {
    #[sensitive(Secret)]
    value: RefCell<T>,
}

#[test]
fn refcell_policy_output_preserves_values_and_fails_closed_on_conflict() {
    let string = RefCellDisplay {
        value: RefCell::new(CANARY.to_owned()),
    };
    assert_eq!(
        string.redacted_display().to_string(),
        "[REDACTED] | RefCell { value: \"[REDACTED]\" }"
    );
    let shared = string.value.borrow();
    let shared_output = string.redacted_display().to_string();
    assert_eq!(
        shared_output,
        "[REDACTED] | RefCell { value: \"[REDACTED]\" }"
    );
    assert!(!shared_output.contains(CANARY));
    drop(shared);
    let mutable = string.value.borrow_mut();
    let conflict = catch_unwind(AssertUnwindSafe(|| string.redacted_display().to_string()))
        .expect("policy-backed RefCell formatting must not panic");
    assert_eq!(conflict, "<borrowed> | <borrowed>");
    assert!(!conflict.contains(CANARY));
    drop(mutable);

    let cow = RefCellDisplay {
        value: RefCell::new(Cow::Borrowed(CANARY)),
    };
    assert_eq!(
        cow.redacted_display().to_string(),
        "[REDACTED] | RefCell { value: \"[REDACTED]\" }"
    );

    let option = RefCellDisplay {
        value: RefCell::new(Some(CANARY.to_owned())),
    };
    assert_eq!(
        option.redacted_display().to_string(),
        "Some([REDACTED]) | RefCell { value: Some(\"[REDACTED]\") }"
    );
}

type ScalarAlias = u64;
type SecretAlias = redactable::Secret;
#[cfg(feature = "ip-address")]
type IpPolicyAlias = redactable::IpAddress;
#[cfg(feature = "ip-address")]
type Ipv4Alias = Ipv4Addr;

#[derive(Clone, Sensitive, Serialize)]
struct SemanticScalars {
    #[sensitive(redactable::Secret)]
    qualified: ScalarAlias,
    #[sensitive(::redactable::Secret)]
    absolute: u32,
    #[sensitive(SecretAlias)]
    aliased_policy: i16,
}

#[derive(SensitiveDisplay)]
#[error("{qualified} {absolute} {aliased_policy}")]
struct SemanticScalarDisplay {
    #[sensitive(redactable::Secret)]
    qualified: ScalarAlias,
    #[sensitive(::redactable::Secret)]
    absolute: u32,
    #[sensitive(SecretAlias)]
    aliased_policy: i16,
}

#[test]
fn qualified_absolute_and_aliased_builtin_policies_use_type_identity() {
    let redacted = SemanticScalars {
        qualified: 91,
        absolute: 92,
        aliased_policy: 93,
    }
    .redact();
    assert_eq!(
        (
            redacted.qualified,
            redacted.absolute,
            redacted.aliased_policy
        ),
        (0, 0, 0)
    );

    let display = SemanticScalarDisplay {
        qualified: 91,
        absolute: 92,
        aliased_policy: 93,
    };
    assert_eq!(display.redacted_display().to_string(), "0 0 0");
}

#[cfg(feature = "ip-address")]
#[derive(Clone, Sensitive, Serialize)]
struct SemanticIpAddresses {
    #[sensitive(redactable::IpAddress)]
    qualified: Ipv4Alias,
    #[sensitive(::redactable::IpAddress)]
    absolute: IpAddr,
    #[sensitive(IpPolicyAlias)]
    aliased_policy: SocketAddr,
}

#[cfg(feature = "ip-address")]
#[derive(SensitiveDisplay)]
#[error("{qualified} {absolute} {aliased_policy}")]
struct SemanticIpAddressDisplay {
    #[sensitive(redactable::IpAddress)]
    qualified: Ipv4Alias,
    #[sensitive(::redactable::IpAddress)]
    absolute: IpAddr,
    #[sensitive(IpPolicyAlias)]
    aliased_policy: SocketAddr,
}

#[cfg(feature = "ip-address")]
#[test]
fn qualified_absolute_and_aliased_ip_policies_use_type_identity() {
    let redacted = SemanticIpAddresses {
        qualified: "192.0.2.7".parse().unwrap(),
        absolute: "192.0.2.8".parse().unwrap(),
        aliased_policy: "192.0.2.9:8443".parse().unwrap(),
    }
    .redact();
    assert_eq!(redacted.qualified, Ipv4Addr::new(0, 0, 0, 7));
    assert_eq!(redacted.absolute, "0.0.0.8".parse::<IpAddr>().unwrap());
    assert_eq!(
        redacted.aliased_policy,
        "0.0.0.9:8443".parse::<SocketAddr>().unwrap()
    );

    let display = SemanticIpAddressDisplay {
        qualified: "192.0.2.7".parse().unwrap(),
        absolute: "192.0.2.8".parse().unwrap(),
        aliased_policy: "192.0.2.9:8443".parse().unwrap(),
    };
    assert_eq!(
        display.redacted_display().to_string(),
        "0.0.0.7 0.0.0.8 0.0.0.9:8443"
    );
}

mod custom {
    use redactable::{RedactionPolicy, TextPolicyKind, TextRedactionPolicy};

    pub struct IpAddress;
    pub struct Secret;

    impl RedactionPolicy for IpAddress {
        type Kind = TextPolicyKind;

        fn policy() -> TextRedactionPolicy {
            TextRedactionPolicy::keep_last(2)
        }
    }

    impl RedactionPolicy for Secret {
        type Kind = TextPolicyKind;

        fn policy() -> TextRedactionPolicy {
            TextRedactionPolicy::keep_last(2)
        }
    }
}

use custom::IpAddress;

#[derive(Clone, Sensitive, Serialize)]
struct CustomPolicyMap {
    #[sensitive(IpAddress)]
    values: HashMap<std::net::IpAddr, String>,
}

#[derive(SensitiveDisplay)]
#[error("{values}")]
struct CustomPolicyMapDisplay {
    #[sensitive(IpAddress)]
    values: HashMap<std::net::IpAddr, String>,
}

#[derive(Clone, Sensitive, Serialize)]
struct CustomSecretPolicy {
    #[sensitive(custom::Secret)]
    value: String,
}

#[test]
fn custom_same_tail_policy_paths_preserve_map_keys() {
    let key: IpAddr = "192.0.2.7".parse().expect("valid test IP");
    let values = HashMap::from([(key, "sensitive-value".to_owned())]);
    let custom = CustomPolicyMap { values }.redact();
    assert!(custom.values.contains_key(&key));
    assert_eq!(custom.values[&key], "*************ue");

    let display = CustomPolicyMapDisplay {
        values: HashMap::from([(key, "sensitive-value".to_owned())]),
    };
    let rendered = display.redacted_display().to_string();
    assert!(rendered.contains("192.0.2.7"));
    assert!(rendered.contains("*************ue"));

    let custom_secret = CustomSecretPolicy {
        value: "sensitive-value".to_owned(),
    }
    .redact();
    assert_eq!(custom_secret.value, "*************ue");
}

#[derive(Clone, Sensitive, Serialize)]
struct CollisionStruct {
    #[sensitive(Secret)]
    __redactable_mapper: String,
    __redactable_f: String,
    __redactable_debug: String,
    field_0: String,
}

#[derive(SensitiveDisplay)]
#[error("{__redacted_value} {__redactable_f:?}")]
struct CollisionDisplay {
    #[sensitive(Secret)]
    __redacted_value: String,
    #[not_sensitive]
    __redactable_f: String,
}

#[test]
fn generated_identifiers_do_not_collide_with_user_fields() {
    let redacted = CollisionStruct {
        __redactable_mapper: CANARY.to_owned(),
        __redactable_f: "f".to_owned(),
        __redactable_debug: "debug".to_owned(),
        field_0: "field".to_owned(),
    }
    .redact();
    assert_eq!(redacted.__redactable_mapper, "[REDACTED]");

    let display = CollisionDisplay {
        __redacted_value: CANARY.to_owned(),
        __redactable_f: "public".to_owned(),
    };
    assert_eq!(
        display.redacted_display().to_string(),
        "[REDACTED] \"public\""
    );
}
