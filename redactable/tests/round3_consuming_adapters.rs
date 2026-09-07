//! Regression coverage for producers whose `Clone` can panic, and for the
//! consuming `tracing` adapters that remain.
//!
//! Logging always clones (D9): `to_redacted()` clones `self`, redacts the
//! clone and serializes it. A `RefCell` with a live mutable borrow therefore
//! panics at the log call, exactly as the borrowing routes always documented.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    sync::Arc,
};

#[cfg(feature = "ip-address")]
use redactable::IpAddress;
#[cfg(feature = "slog")]
use redactable::slog::SlogRedactedExt;
#[cfg(feature = "tracing")]
use redactable::tracing::{
    IntoTracingRedactedDebugExt, TracingRedactedDebugExt, TracingRedactedExt,
};
#[cfg(feature = "tracing-valuable")]
use redactable::tracing::{IntoTracingRedactedValuableExt, TracingValuableExt};
use redactable::{
    Redactable, RedactableWithFormatter, Secret, Sensitive, SensitiveDisplay, ToRedacted,
};
use redactable_test_fixtures::PublicRedactedEvent;
#[cfg(feature = "tracing-valuable")]
use valuable::{Valuable, Value as ValuableValue, Visit};

#[derive(Clone, Sensitive, serde::Serialize)]
struct BorrowEvent {
    #[sensitive(Secret)]
    secret: RefCell<String>,
}

#[cfg(feature = "tracing-valuable")]
impl Valuable for BorrowEvent {
    fn as_value(&self) -> ValuableValue<'_> {
        ValuableValue::Unit
    }

    fn visit(&self, visitor: &mut dyn Visit) {
        visitor.visit_value(ValuableValue::Unit);
    }
}

fn borrowed_event() -> BorrowEvent {
    BorrowEvent {
        secret: RefCell::new("round3-secret-canary".to_owned()),
    }
}

// Only the consuming `tracing` adapters still take a borrow-conflicted value;
// `tracing-valuable` implies `tracing`, so one gate covers both callers.
#[cfg(feature = "tracing")]
fn borrow_conflicted_event() -> BorrowEvent {
    let event = borrowed_event();
    let borrow = event.secret.borrow_mut();
    std::mem::forget(borrow);
    event
}

#[test]
fn the_producer_documents_live_refcell_borrow_panic() {
    let event = borrowed_event();
    let _borrow = event.secret.borrow_mut();
    let result = catch_unwind(AssertUnwindSafe(|| event.to_redacted()));
    assert!(result.is_err());
}

#[cfg(feature = "slog")]
#[test]
fn slog_redacted_json_documents_live_refcell_borrow_panic() {
    let event = borrowed_event();
    let _borrow = event.secret.borrow_mut();
    let result = catch_unwind(AssertUnwindSafe(|| event.slog_redacted_json()));
    assert!(result.is_err());
}

#[cfg(feature = "tracing")]
#[test]
fn consuming_tracing_debug_redacts_without_clone() {
    let output = format!(
        "{:?}",
        borrow_conflicted_event().into_tracing_redacted_debug()
    );
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains("round3-secret-canary"));
}

#[cfg(feature = "tracing")]
#[test]
fn borrowed_tracing_paths_document_live_refcell_borrow_panics() {
    let event = borrowed_event();
    let _borrow = event.secret.borrow_mut();

    assert!(catch_unwind(AssertUnwindSafe(|| event.tracing_redacted_debug())).is_err());
    assert!(catch_unwind(AssertUnwindSafe(|| event.tracing_redacted())).is_err());
}

#[cfg(feature = "tracing-valuable")]
#[test]
fn consuming_tracing_valuable_redacts_without_clone() {
    let output = borrow_conflicted_event().into_tracing_redacted_valuable();
    assert_eq!(output.into_inner().secret.borrow().as_str(), "[REDACTED]");
}

#[cfg(feature = "tracing-valuable")]
#[test]
fn borrowed_tracing_valuable_documents_live_refcell_borrow_panic() {
    let event = borrowed_event();
    let _borrow = event.secret.borrow_mut();
    assert!(catch_unwind(AssertUnwindSafe(|| event.tracing_redacted_valuable())).is_err());
}

// Regression for the round-06 B-1 source-compatibility defect (external-review-3
// "sensitive scalar" finding on the consuming route): a struct whose only
// non-string sensitive field is a `#[sensitive(Secret)]` plain scalar must stay
// usable through the consuming adapters. Under the removed owned-capability
// hierarchy the scalar had no owned policy dispatch, which denied its whole
// container the capability the adapters required, so the structural producer and
// `slog_redacted_json` failed to compile even though `.redact()` worked. Both
// now route through `.redact()`, so the shape cannot diverge from the
// structural traversal again. These tests pin the surviving routes.
#[derive(Clone, Sensitive, serde::Serialize)]
struct ScalarEvent {
    #[sensitive(Secret)]
    account_number: u64,
    #[sensitive(Secret)]
    note: String,
}

/// Distinct scalar value so its digits can be asserted absent from redacted output.
const SCALAR_SENTINEL: u64 = 987_654_321;
const SCALAR_SENTINEL_DIGITS: &str = "987654321";
const SCALAR_STRING_CANARY: &str = "round3-scalar-canary";

fn scalar_event() -> ScalarEvent {
    ScalarEvent {
        account_number: SCALAR_SENTINEL,
        note: SCALAR_STRING_CANARY.to_owned(),
    }
}

#[test]
fn sensitive_scalar_still_redacts_structurally() {
    // Baseline path (`.redact()`) was never broken; assert it still holds so the
    // consuming-adapter fix cannot silently regress structural traversal.
    let redacted = scalar_event().redact();
    assert_eq!(redacted.account_number, 0);
    assert_eq!(redacted.note, "[REDACTED]");
}

#[test]
fn sensitive_scalar_reaches_the_generated_producer() {
    // The structural route did not compile for this shape before the fix.
    let rendered = scalar_event().to_redacted().json().to_string();
    assert!(rendered.contains("\"account_number\":0"));
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains(SCALAR_SENTINEL_DIGITS));
    assert!(!rendered.contains(SCALAR_STRING_CANARY));
}

#[cfg(feature = "slog")]
#[test]
fn sensitive_scalar_consuming_slog_json_redacts_without_clone() {
    // `slog_redacted_json` is the pre-existing public API whose rebinding to the
    // owned capability caused the regression; prove the scalar redacts to 0 in
    // the serialized JSON and the sentinel/canary never leak.
    let rendered = scalar_event().slog_redacted_json().json().to_string();
    assert!(rendered.contains("[REDACTED]"));
    assert!(rendered.contains("\"account_number\":0"));
    assert!(!rendered.contains(SCALAR_SENTINEL_DIGITS));
    assert!(!rendered.contains(SCALAR_STRING_CANARY));
}

// Review-round B-A dissolved with the owned-capability hierarchy. That
// hierarchy generated an owned traversal bound that did not honor
// `#[redactable(recursive)]`, so a recursive field formed a trait-solver cycle
// and every consuming adapter rejected the type with an `E0275` overflow. The
// consuming adapters now redact through `.redact()`, which has always honored
// the override, so recursive types work on the consuming route as well.
//
// These tests pin structural `.redact()` and borrowed `SensitiveDisplay`
// formatting, which already worked. Consuming adapters that previously failed
// to compile must use the same structural traversal.
#[derive(Clone, Sensitive, serde::Serialize)]
struct RecursiveSecretNode {
    #[sensitive(Secret)]
    secret: String,
    #[redactable(recursive)]
    next: Option<Box<RecursiveSecretNode>>,
}

const RECURSIVE_SECRET_CANARY: &str = "round3-recursive-secret-canary";
const RECURSIVE_NESTED_SECRET_CANARY: &str = "round3-recursive-nested-secret-canary";

fn recursive_secret_node() -> RecursiveSecretNode {
    RecursiveSecretNode {
        secret: RECURSIVE_SECRET_CANARY.to_owned(),
        next: Some(Box::new(RecursiveSecretNode {
            secret: RECURSIVE_NESTED_SECRET_CANARY.to_owned(),
            next: None,
        })),
    }
}

#[test]
fn recursive_derive_still_redacts_structurally() {
    let redacted = format!("{:?}", recursive_secret_node().redact());
    assert!(redacted.contains("[REDACTED]"));
    assert!(!redacted.contains(RECURSIVE_SECRET_CANARY));
    assert!(!redacted.contains(RECURSIVE_NESTED_SECRET_CANARY));
}

// The B-A closure: this call did not compile before the owned hierarchy was
// deleted (`E0275` overflow evaluating `Box<RecursiveSecretNode>:
// DirectRedactableOwned`). It must now redact the whole recursive graph.
#[test]
fn recursive_derive_redacts_through_the_generated_producer() {
    let output = recursive_secret_node().to_redacted().json().to_string();
    // Positive first, so a structurally broken output cannot let the negative
    // assertions below pass vacuously.
    assert!(
        output.contains("secret"),
        "output should be structural: {output}"
    );
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains(RECURSIVE_SECRET_CANARY));
    // The nested node behind the `#[redactable(recursive)]` field must redact too.
    assert!(!output.contains(RECURSIVE_NESTED_SECRET_CANARY));
}

#[cfg(feature = "slog")]
#[test]
fn recursive_derive_redacts_through_consuming_slog_json() {
    let rendered = recursive_secret_node()
        .slog_redacted_json()
        .json()
        .to_string();
    assert!(
        rendered.contains("secret"),
        "output should be structural: {rendered}"
    );
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains(RECURSIVE_SECRET_CANARY));
    assert!(!rendered.contains(RECURSIVE_NESTED_SECRET_CANARY));
}

#[cfg(feature = "tracing")]
#[test]
fn recursive_derive_redacts_through_consuming_tracing_debug() {
    let output = format!(
        "{:?}",
        recursive_secret_node().into_tracing_redacted_debug()
    );
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains(RECURSIVE_SECRET_CANARY));
    assert!(!output.contains(RECURSIVE_NESTED_SECRET_CANARY));
}

#[derive(SensitiveDisplay)]
#[error("{secret} {next:?}")]
struct RecursiveSecretDisplayNode {
    #[sensitive(Secret)]
    secret: String,
    #[redactable(recursive)]
    next: Option<Box<RecursiveSecretDisplayNode>>,
}

#[test]
fn recursive_display_derive_still_redacts_by_reference() {
    let node = RecursiveSecretDisplayNode {
        secret: RECURSIVE_SECRET_CANARY.to_owned(),
        next: Some(Box::new(RecursiveSecretDisplayNode {
            secret: RECURSIVE_NESTED_SECRET_CANARY.to_owned(),
            next: None,
        })),
    };
    let rendered = node.redacted_display().to_string();
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains(RECURSIVE_SECRET_CANARY));
    assert!(!rendered.contains(RECURSIVE_NESTED_SECRET_CANARY));
}

// Closes review advisory F-3: every prior review proved the map/set/IP-policy
// consuming routes only with throwaway probes, so nothing in the suite pinned
// them. These leaf kinds are exactly where the B-1 class lived (under the
// removed owned hierarchy, a kind carrying borrowed dispatch but no owned
// dispatch silently denied its whole container the consuming route), so the
// collection and IP routes get the same standing coverage the scalar route
// earned.
#[derive(Clone, Sensitive, serde::Serialize)]
struct CollectionEvent {
    #[sensitive(Secret)]
    tokens: BTreeMap<String, String>,
    #[sensitive(Secret)]
    tags: BTreeSet<String>,
}

const MAP_VALUE_CANARY: &str = "round3-map-value-canary";
const SET_VALUE_CANARY: &str = "round3-set-value-canary";

fn collection_event() -> CollectionEvent {
    CollectionEvent {
        tokens: BTreeMap::from([("api".to_owned(), MAP_VALUE_CANARY.to_owned())]),
        tags: BTreeSet::from([SET_VALUE_CANARY.to_owned()]),
    }
}

#[test]
fn sensitive_map_and_set_reach_the_generated_producer() {
    let output = collection_event().to_redacted().json();
    // The producer serializes the redacted value, so map keys survive and the
    // set collapses exactly as structural traversal leaves them.
    assert_eq!(
        output,
        serde_json::json!({"tokens":{"api":"[REDACTED]"},"tags":["[REDACTED]"]})
    );
    let output = output.to_string();
    let redacted = collection_event().redact();
    assert_eq!(
        redacted.tokens,
        BTreeMap::from([("api".to_owned(), "[REDACTED]".to_owned())])
    );
    assert_eq!(redacted.tags, BTreeSet::from(["[REDACTED]".to_owned()]));
    assert!(!output.contains(MAP_VALUE_CANARY));
    assert!(!output.contains(SET_VALUE_CANARY));
}

#[cfg(feature = "slog")]
#[test]
fn sensitive_map_and_set_consuming_slog_json_redacts_without_clone() {
    let rendered = collection_event().slog_redacted_json().json().to_string();
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains(MAP_VALUE_CANARY));
    assert!(!rendered.contains(SET_VALUE_CANARY));
}

#[cfg(feature = "ip-address")]
#[derive(Clone, Sensitive, serde::Serialize)]
struct IpCollectionEvent {
    #[sensitive(IpAddress)]
    client_ip: String,
    #[sensitive(IpAddress)]
    peer_ips: BTreeMap<u8, String>,
    #[sensitive(IpAddress)]
    seen_ips: BTreeSet<String>,
}

#[cfg(feature = "ip-address")]
const IP_CANARY: &str = "203.0.113.42";
#[cfg(feature = "ip-address")]
const IP_MAP_CANARY: &str = "198.51.100.7";
#[cfg(feature = "ip-address")]
const IP_SET_CANARY: &str = "192.0.2.55";

#[cfg(feature = "ip-address")]
fn ip_collection_event() -> IpCollectionEvent {
    IpCollectionEvent {
        client_ip: IP_CANARY.to_owned(),
        peer_ips: BTreeMap::from([(1u8, IP_MAP_CANARY.to_owned())]),
        seen_ips: BTreeSet::from([IP_SET_CANARY.to_owned()]),
    }
}

#[cfg(feature = "ip-address")]
#[test]
fn ip_policy_bare_map_and_set_reach_the_generated_producer() {
    let output = ip_collection_event().to_redacted().json().to_string();
    // Positive first, so an empty or structurally broken output cannot let the
    // negative assertions below pass vacuously.
    assert!(
        output.contains("client_ip"),
        "output should be structural: {output}"
    );
    let redacted = ip_collection_event().redact();
    assert_eq!(redacted.client_ip, "********3.42");
    assert_eq!(redacted.peer_ips[&1], "********00.7");
    assert_eq!(redacted.seen_ips, BTreeSet::from(["******2.55".to_owned()]));
    // The IP policy masks the leading octets; no raw address may survive on any
    // of the bare, map-value, or set-element routes.
    assert!(!output.contains(IP_CANARY));
    assert!(!output.contains(IP_MAP_CANARY));
    assert!(!output.contains(IP_SET_CANARY));
}

#[cfg(all(feature = "ip-address", feature = "slog"))]
#[test]
fn ip_policy_bare_map_and_set_consuming_slog_json_redacts_without_clone() {
    let rendered = ip_collection_event()
        .slog_redacted_json()
        .json()
        .to_string();
    assert!(
        rendered.contains("client_ip"),
        "output should be structural: {rendered}"
    );
    assert!(rendered.contains('*'), "IP policy should mask: {rendered}");
    assert!(!rendered.contains(IP_CANARY));
    assert!(!rendered.contains(IP_MAP_CANARY));
    assert!(!rendered.contains(IP_SET_CANARY));
}

// =============================================================================
// The accepted residual: Arc/Rc traversal still clones its referent
// =============================================================================
//
// The consuming adapters redact the owned value and never clone it. Traversal
// through `Arc`/`Rc` is the documented exception: another owner may still hold
// the referent, so redacting it must clone. Cloning a `RefCell` panics while it
// is mutably borrowed, so `Arc<RefCell<T>>` behind a consuming adapter still
// panics under a live borrow.
//
// This is the accepted cost of deleting the owned-capability hierarchy, which
// existed only to reject this shape statically. `Arc<RefCell<T>>` is
// `!Send + !Sync` (RefCell is not Sync) and an anti-pattern regardless; the
// supported answer is unique ownership (`Box`), covered by
// `consuming_output_redacts_without_clone` above. These tests pin the residual
// so it stays a known, documented contract rather than a surprise.
//
// Mirrors the `borrowed_output_documents_live_refcell_borrow_panic` pattern:
// `catch_unwind` proves the panic without aborting the suite.

// `serde` only implements `Serialize` for `Arc`/`Rc` under its `rc` feature,
// which this workspace does not enable. `Sensitive` requires `Serialize`, so
// these two shapes carry a handwritten one over the shared referent. It runs
// after redaction; the panic under test still comes from cloning the referent.
#[derive(Clone, Sensitive)]
struct SharedOwnerEvent {
    #[sensitive(Secret)]
    secret: Arc<RefCell<String>>,
}

impl serde::Serialize for SharedOwnerEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.secret.borrow())
    }
}

#[derive(Clone, Sensitive)]
struct RcOwnerEvent {
    #[sensitive(Secret)]
    secret: Rc<RefCell<String>>,
}

impl serde::Serialize for RcOwnerEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.secret.borrow())
    }
}

const SHARED_OWNER_CANARY: &str = "round3-shared-owner-canary";

// `clippy::arc_with_non_send_sync` fires on the construction below, reporting
// exactly the point these tests exist to record: `Arc<RefCell<String>>` is not
// `Send + Sync` because `RefCell` is not `Sync`. That anti-pattern is the
// subject under test, not an oversight, so the lint is allowed here only.
#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn arc_refcell_producer_panics_under_a_live_mutable_borrow() {
    let event = SharedOwnerEvent {
        secret: Arc::new(RefCell::new(SHARED_OWNER_CANARY.to_owned())),
    };
    let _borrow = event.secret.borrow_mut();
    let result = catch_unwind(AssertUnwindSafe(|| event.to_redacted()));
    assert!(
        result.is_err(),
        "Arc traversal must clone its referent, so a live mutable borrow panics"
    );
}

#[test]
fn rc_refcell_producer_panics_under_a_live_mutable_borrow() {
    let event = RcOwnerEvent {
        secret: Rc::new(RefCell::new(SHARED_OWNER_CANARY.to_owned())),
    };
    let _borrow = event.secret.borrow_mut();
    let result = catch_unwind(AssertUnwindSafe(|| event.to_redacted()));
    assert!(
        result.is_err(),
        "Rc traversal must clone its referent, so a live mutable borrow panics"
    );
}

// The same shape is fine when nothing holds a borrow: the shape now compiles
// (the deleted hierarchy rejected it outright) and redacts correctly.
#[test]
#[allow(clippy::arc_with_non_send_sync)] // Same anti-pattern under test; see above.
fn arc_refcell_redacts_when_unborrowed() {
    let event = SharedOwnerEvent {
        secret: Arc::new(RefCell::new(SHARED_OWNER_CANARY.to_owned())),
    };
    let output = event.to_redacted().json().to_string();
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains(SHARED_OWNER_CANARY));
}

// =============================================================================
// E0446: a public type must not leak its private field types
// =============================================================================
//
// The owned-capability hierarchy emitted
// `type Driver = __RedactableOwnedCapability<Self, #field_types..>` as a public
// associated type, so a `pub` container holding a private field type failed to
// compile with `error[E0446]: private type ... in public interface`.
//
// `redactable-test-fixtures` is a library, so the public/private boundary is
// real there and E0446 is enforced at its compile time. Depending on the
// fixture here makes that guard load-bearing for this suite: if the derive ever
// leaks field visibility again, the fixture crate fails to build and this test
// cannot run. The runtime assertions confirm the shape also behaves correctly.
// See `tests/ui/sensitive_private_field_type_public_struct_ok.rs` for the
// trybuild counterpart.
#[test]
fn public_struct_with_private_field_type_compiles_and_redacts() {
    let event = PublicRedactedEvent::new("e0446-token-canary", "e0446-note-canary");
    assert_eq!(event.detail_note(), "e0446-note-canary");

    let redacted = event.redact();
    assert_eq!(redacted.token, "[REDACTED]");
    // The unannotated private field is walked, not redacted.
    assert_eq!(redacted.detail_note(), "e0446-note-canary");
}

#[test]
fn public_struct_with_private_field_type_redacts_through_the_producer() {
    let event = PublicRedactedEvent::new("e0446-token-canary", "e0446-note-canary");
    let output = event.to_redacted().json().to_string();
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains("e0446-token-canary"));
}
