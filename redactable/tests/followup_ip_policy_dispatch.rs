#![cfg(feature = "ip-address")]

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    marker::PhantomData,
    net::IpAddr,
};

use redactable::{
    __private::{PolicyField, PolicyFieldRef, PolicyMapper},
    IpAddress, PolicyApplicable, PolicyApplicableRef, Redactable, RedactableWithFormatter,
    RedactionPolicy, Sensitive, SensitiveDisplay, SensitiveValue, TextPolicyKind,
    TextRedactionPolicy, apply_policy, apply_policy_ref,
};

type ClientIp = IpAddr;
type WrappedIp = SensitiveValue<ClientIp, IpAddress>;

#[cfg(feature = "slog")]
mod support {
    pub(crate) mod slog_capture;
}

#[derive(Clone, Sensitive)]
#[cfg_attr(feature = "slog", derive(serde::Serialize))]
struct BareAlias {
    #[sensitive(IpAddress)]
    value: ClientIp,
}

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct BareAliasDisplay {
    #[sensitive(IpAddress)]
    value: ClientIp,
}

#[derive(Clone, Sensitive)]
#[cfg_attr(feature = "slog", derive(serde::Serialize))]
struct SupportedRecursiveRoutes {
    #[sensitive(IpAddress)]
    wrapped: Vec<WrappedIp>,
    #[sensitive(IpAddress)]
    nested: HashMap<u16, Vec<Option<WrappedIp>>>,
    #[sensitive(IpAddress)]
    set: BTreeSet<WrappedIp>,
    #[sensitive(IpAddress)]
    text_values: HashMap<u8, String>,
}

#[derive(SensitiveDisplay)]
#[error("{nested:?} {set:?}")]
struct SupportedRecursiveDisplay {
    #[sensitive(IpAddress)]
    nested: HashMap<u16, Vec<Option<WrappedIp>>>,
    #[sensitive(IpAddress)]
    set: BTreeSet<WrappedIp>,
}

#[derive(Clone, Sensitive)]
#[cfg_attr(feature = "slog", derive(serde::Serialize))]
struct GenericPolicy<P: RedactionPolicy> {
    #[sensitive(P)]
    text_values: HashMap<bool, String>,
    marker: PhantomData<P>,
}

mod custom {
    use super::*;

    pub struct IpAddress;

    impl RedactionPolicy for IpAddress {
        type Kind = TextPolicyKind;

        fn policy() -> TextRedactionPolicy {
            TextRedactionPolicy::keep_last(2)
        }
    }
}

#[derive(Clone, Sensitive)]
#[cfg_attr(feature = "slog", derive(serde::Serialize))]
struct GenericRawIpKeyMaps<P: RedactionPolicy> {
    #[sensitive(P)]
    hash: HashMap<IpAddr, String>,
    #[sensitive(P)]
    tree: BTreeMap<IpAddr, String>,
    marker: PhantomData<P>,
}

#[derive(SensitiveDisplay)]
#[error("{hash:?} {tree:?}")]
struct GenericRawIpKeyMapsDisplay<P: RedactionPolicy> {
    #[sensitive(P)]
    #[redactable(generated_formatting)]
    hash: HashMap<IpAddr, String>,
    #[sensitive(P)]
    #[redactable(generated_formatting)]
    tree: BTreeMap<IpAddr, String>,
    marker: PhantomData<P>,
}

fn ip(value: &str) -> IpAddr {
    value.parse().expect("valid IP test value")
}

fn generic_apply<P, T>(value: T) -> T
where
    P: RedactionPolicy,
    T: PolicyField<P>,
{
    apply_policy::<P, _>(value)
}

fn generic_apply_ref<P, T>(value: &T) -> <T as PolicyFieldRef<P>>::Output
where
    P: RedactionPolicy,
    T: PolicyFieldRef<P> + ?Sized,
{
    apply_policy_ref::<P, _>(value)
}

#[test]
fn bare_alias_and_supported_workarounds_redact_without_canaries() {
    const BARE: &str = "203.0.113.71";
    const WRAPPED: &str = "203.0.113.72";
    const NESTED: &str = "203.0.113.73";
    const SET: &str = "203.0.113.74";
    const TEXT: &str = "203.0.113.173";

    let bare = BareAlias { value: ip(BARE) }.redact();
    assert_eq!(bare.value, ip("0.0.0.71"));
    assert!(!format!("{bare:?}").contains(BARE));

    let display = BareAliasDisplay { value: ip(BARE) }
        .redacted_display()
        .to_string();
    assert_eq!(display, "0.0.0.71");
    assert!(!display.contains(BARE));

    let recursive = SupportedRecursiveRoutes {
        wrapped: vec![SensitiveValue::from(ip(WRAPPED))],
        nested: HashMap::from([(7, vec![Some(SensitiveValue::from(ip(NESTED)))])]),
        set: BTreeSet::from([SensitiveValue::from(ip(SET))]),
        text_values: HashMap::from([(1, TEXT.to_owned())]),
    }
    .redact();
    assert_eq!(recursive.wrapped[0].expose(), &ip("0.0.0.72"));
    assert_eq!(
        recursive.nested[&7][0]
            .as_ref()
            .expect("wrapped IP")
            .expose(),
        &ip("0.0.0.73")
    );
    assert_eq!(
        recursive.set.first().expect("wrapped IP").expose(),
        &ip("0.0.0.74")
    );
    assert_eq!(recursive.text_values[&1], "*********.173");
    let rendered = format!("{recursive:?}");
    assert!(!rendered.contains(WRAPPED));
    assert!(!rendered.contains(NESTED));
    assert!(!rendered.contains(SET));
    assert!(!rendered.contains(TEXT));

    let display = SupportedRecursiveDisplay {
        nested: HashMap::from([(7, vec![Some(SensitiveValue::from(ip(NESTED)))])]),
        set: BTreeSet::from([SensitiveValue::from(ip(SET))]),
    }
    .redacted_display()
    .to_string();
    assert!(display.contains("0.0.0.73"));
    assert!(display.contains("0.0.0.74"));
    assert!(!display.contains(NESTED));
    assert!(!display.contains(SET));
}

#[test]
fn generic_policy_dispatch_waits_for_the_concrete_kind() {
    const CANARY: &str = "198.51.100.199";
    let value = GenericPolicy::<IpAddress> {
        text_values: HashMap::from([(true, CANARY.to_owned())]),
        marker: PhantomData,
    }
    .redact();
    assert_eq!(value.text_values[&true], "**********.199");
    assert!(!format!("{value:?}").contains(CANARY));
}

#[test]
fn free_policy_functions_use_kind_aware_dispatch() {
    const BARE: &str = "203.0.113.81";
    const WRAPPED: &str = "203.0.113.82";
    const TEXT: &str = "203.0.113.183";

    let bare = generic_apply::<IpAddress, _>(ip(BARE));
    assert_eq!(bare, ip("0.0.0.81"));
    let bare_ref = generic_apply_ref::<IpAddress, _>(&ip(BARE));
    assert_eq!(bare_ref, "0.0.0.81");

    let wrapped = HashMap::from([(1_u8, SensitiveValue::from(ip(WRAPPED)))]);
    let redacted = generic_apply::<IpAddress, _>(wrapped);
    assert_eq!(redacted[&1].expose(), &ip("0.0.0.82"));

    let text = HashMap::from([(true, TEXT.to_owned())]);
    let redacted_ref = generic_apply_ref::<IpAddress, _>(&text);
    assert_eq!(redacted_ref[&true], "*********.183");
    assert!(!format!("{redacted_ref:?}").contains(TEXT));
}

#[test]
fn generic_raw_ip_key_maps_remain_available_to_text_policy_kinds() {
    const CANARY: &str = "ordinary-text-value";
    let key = ip("192.0.2.8");
    let hash = HashMap::from([(key, CANARY.to_owned())]);
    let tree = BTreeMap::from([(key, CANARY.to_owned())]);

    let redacted = GenericRawIpKeyMaps::<custom::IpAddress> {
        hash: hash.clone(),
        tree: tree.clone(),
        marker: PhantomData,
    }
    .redact();
    assert_eq!(redacted.hash[&key], "*****************ue");
    assert_eq!(redacted.tree[&key], "*****************ue");
    assert!(redacted.hash.contains_key(&key));
    assert!(redacted.tree.contains_key(&key));

    let display = GenericRawIpKeyMapsDisplay::<custom::IpAddress> {
        hash,
        tree,
        marker: PhantomData,
    }
    .redacted_display()
    .to_string();
    assert!(display.contains("192.0.2.8"));
    assert!(display.contains("*****************ue"));
    assert!(!display.contains(CANARY));

    let direct = PolicyApplicable::apply_policy::<custom::IpAddress, _>(
        HashMap::from([(key, CANARY.to_owned())]),
        &PolicyMapper,
    );
    assert_eq!(direct[&key], "*****************ue");
    assert!(direct.contains_key(&key));

    let direct_source = BTreeMap::from([(key, CANARY.to_owned())]);
    let direct_ref = PolicyApplicableRef::apply_policy_ref::<custom::IpAddress, _>(
        &direct_source,
        &PolicyMapper,
    );
    assert_eq!(direct_ref[&key], "*****************ue");
    assert!(direct_ref.contains_key(&key));
}

#[cfg(feature = "slog")]
#[test]
fn annotated_wrappers_stay_redacted_through_slog() {
    use redactable::slog::SlogRedactedExt;
    use support::slog_capture::{CapturedValue, CapturingSerializer, serialize_to_capture};

    const NESTED: &str = "198.51.100.201";
    const SET: &str = "198.51.100.202";
    let event = SupportedRecursiveRoutes {
        wrapped: vec![SensitiveValue::from(ip("198.51.100.200"))],
        nested: HashMap::from([(7, vec![Some(SensitiveValue::from(ip(NESTED)))])]),
        set: BTreeSet::from([SensitiveValue::from(ip(SET))]),
        text_values: HashMap::from([(1, "198.51.100.203".to_owned())]),
    };

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&event.slog_redacted_json(), "event", &mut serializer);
    let Some(CapturedValue::Serde(json)) = serializer.get("event") else {
        panic!("expected structured slog JSON");
    };
    let rendered = json.to_string();
    assert!(rendered.contains("0.0.0.201"));
    assert!(rendered.contains("0.0.0.202"));
    assert!(!rendered.contains(NESTED));
    assert!(!rendered.contains(SET));
}
