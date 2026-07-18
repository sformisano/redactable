//! Regression coverage for clone-backed borrowed adapters and consuming alternatives.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    panic::{AssertUnwindSafe, catch_unwind},
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
#[cfg(feature = "json")]
use redactable::{IntoRedactedJsonExt, RedactedJsonExt};
use redactable::{
    IntoRedactedOutputExt, Redactable, RedactableWithFormatter, RedactedOutput, RedactedOutputExt,
    Secret, Sensitive, SensitiveDisplay, ToRedactedOutput,
};

#[derive(Clone, Sensitive, serde::Serialize)]
struct BorrowEvent {
    #[sensitive(Secret)]
    secret: RefCell<String>,
}

#[cfg(feature = "tracing-valuable")]
impl valuable::Valuable for BorrowEvent {
    fn as_value(&self) -> valuable::Value<'_> {
        valuable::Value::Unit
    }

    fn visit(&self, visitor: &mut dyn valuable::Visit) {
        visitor.visit_value(valuable::Value::Unit);
    }
}

fn borrowed_event() -> BorrowEvent {
    BorrowEvent {
        secret: RefCell::new("round3-secret-canary".to_owned()),
    }
}

fn borrow_conflicted_event() -> BorrowEvent {
    let event = borrowed_event();
    let borrow = event.secret.borrow_mut();
    std::mem::forget(borrow);
    event
}

#[test]
fn consuming_output_redacts_without_clone() {
    let output = borrow_conflicted_event().into_redacted_output();
    let output = match output {
        RedactedOutput::Text(output) => output,
        _ => panic!("structural output should be text"),
    };
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains("round3-secret-canary"));
}

#[test]
fn borrowed_output_documents_live_refcell_borrow_panic() {
    let event = borrowed_event();
    let _borrow = event.secret.borrow_mut();
    let result = catch_unwind(AssertUnwindSafe(|| {
        event.redacted_output().to_redacted_output()
    }));
    assert!(result.is_err());
}

#[cfg(feature = "json")]
#[test]
fn consuming_json_redacts_without_clone() {
    let output = borrow_conflicted_event()
        .into_redacted_json()
        .to_redacted_output();
    let output = match output {
        RedactedOutput::Json(output) => output,
        _ => panic!("JSON adapter should produce JSON output"),
    };
    let rendered = output.to_string();
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains("round3-secret-canary"));
}

#[cfg(feature = "json")]
#[test]
fn borrowed_json_documents_live_refcell_borrow_panic() {
    let event = borrowed_event();
    let _borrow = event.secret.borrow_mut();
    let result = catch_unwind(AssertUnwindSafe(|| {
        event.redacted_json().to_redacted_output()
    }));
    assert!(result.is_err());
}

#[cfg(feature = "slog")]
#[test]
fn consuming_slog_json_redacts_without_clone() {
    let output = borrow_conflicted_event()
        .slog_redacted_json()
        .to_redacted_output();
    let output = match output {
        RedactedOutput::Json(output) => output,
        _ => panic!("slog JSON adapter should produce JSON output"),
    };
    let rendered = output.to_string();
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains("round3-secret-canary"));
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
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            event.redacted_output().tracing_redacted()
        }))
        .is_err()
    );
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
// container the capability the adapters required, so `into_redacted_output` and
// `slog_redacted_json` failed to compile even though `.redact()` worked. The
// adapters now route through `.redact()`, so the shape cannot diverge from the
// borrowed path again. These tests pin all three routes.
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
fn sensitive_scalar_still_redacts_by_clone() {
    // Baseline path (`.redact()`) was never broken; assert it still holds so the
    // consuming-route fix cannot silently regress the borrowed structural route.
    let redacted = scalar_event().redact();
    assert_eq!(redacted.account_number, 0);
    assert_eq!(redacted.note, "[REDACTED]");
}

#[test]
fn sensitive_scalar_consuming_output_redacts_without_clone() {
    // `into_redacted_output` did not compile for this shape before the fix.
    let output = match scalar_event().into_redacted_output() {
        RedactedOutput::Text(output) => output,
        other => panic!("structural output should be text, got {other:?}"),
    };
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains(SCALAR_SENTINEL_DIGITS));
    assert!(!output.contains(SCALAR_STRING_CANARY));
}

#[cfg(feature = "slog")]
#[test]
fn sensitive_scalar_consuming_slog_json_redacts_without_clone() {
    // `slog_redacted_json` is the pre-existing public API whose rebinding to the
    // owned capability caused the regression; prove the scalar redacts to 0 in
    // the serialized JSON and the sentinel/canary never leak.
    let rendered = match scalar_event().slog_redacted_json().to_redacted_output() {
        RedactedOutput::Json(output) => output.to_string(),
        other => panic!("slog JSON adapter should produce JSON output, got {other:?}"),
    };
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
// These tests pin both directions for one shape: the borrowed route
// (`.redact()`, `SensitiveDisplay`) that always worked must not regress, and
// the consuming route that used to be a compile error must now redact.
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
fn recursive_derive_still_redacts_by_clone() {
    let redacted = format!("{:?}", recursive_secret_node().redact());
    assert!(redacted.contains("[REDACTED]"));
    assert!(!redacted.contains(RECURSIVE_SECRET_CANARY));
    assert!(!redacted.contains(RECURSIVE_NESTED_SECRET_CANARY));
}

// The B-A closure: this call did not compile before the owned hierarchy was
// deleted (`E0275` overflow evaluating `Box<RecursiveSecretNode>:
// DirectRedactableOwned`). It must now redact the whole recursive graph.
#[test]
fn recursive_derive_redacts_through_consuming_output() {
    let output = match recursive_secret_node().into_redacted_output() {
        RedactedOutput::Text(output) => output,
        other => panic!("structural output should be text, got {other:?}"),
    };
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

#[cfg(feature = "json")]
#[test]
fn recursive_derive_redacts_through_consuming_json() {
    let rendered = match recursive_secret_node()
        .into_redacted_json()
        .to_redacted_output()
    {
        RedactedOutput::Json(output) => output.to_string(),
        other => panic!("json adapter should produce JSON output, got {other:?}"),
    };
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains(RECURSIVE_SECRET_CANARY));
    assert!(!rendered.contains(RECURSIVE_NESTED_SECRET_CANARY));
}

#[cfg(feature = "slog")]
#[test]
fn recursive_derive_redacts_through_consuming_slog_json() {
    let rendered = match recursive_secret_node()
        .slog_redacted_json()
        .to_redacted_output()
    {
        RedactedOutput::Json(output) => output.to_string(),
        other => panic!("slog JSON adapter should produce JSON output, got {other:?}"),
    };
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
fn sensitive_map_and_set_consuming_output_redacts_without_clone() {
    let output = match collection_event().into_redacted_output() {
        RedactedOutput::Text(output) => output,
        other => panic!("structural output should be text, got {other:?}"),
    };
    assert!(output.contains("[REDACTED]"));
    // Map keys are deliberately preserved; only values redact.
    assert!(output.contains("api"));
    assert!(!output.contains(MAP_VALUE_CANARY));
    assert!(!output.contains(SET_VALUE_CANARY));
}

#[cfg(feature = "json")]
#[test]
fn sensitive_map_and_set_consuming_json_redacts_without_clone() {
    let rendered = match collection_event().into_redacted_json().to_redacted_output() {
        RedactedOutput::Json(output) => output.to_string(),
        other => panic!("json adapter should produce JSON output, got {other:?}"),
    };
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains(MAP_VALUE_CANARY));
    assert!(!rendered.contains(SET_VALUE_CANARY));
}

#[cfg(feature = "slog")]
#[test]
fn sensitive_map_and_set_consuming_slog_json_redacts_without_clone() {
    let rendered = match collection_event().slog_redacted_json().to_redacted_output() {
        RedactedOutput::Json(output) => output.to_string(),
        other => panic!("slog JSON adapter should produce JSON output, got {other:?}"),
    };
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
fn ip_policy_bare_map_and_set_consuming_output_redacts_without_clone() {
    let output = match ip_collection_event().into_redacted_output() {
        RedactedOutput::Text(output) => output,
        other => panic!("structural output should be text, got {other:?}"),
    };
    // Positive first, so an empty or structurally broken output cannot let the
    // negative assertions below pass vacuously.
    assert!(
        output.contains("client_ip"),
        "output should be structural: {output}"
    );
    assert!(output.contains('*'), "IP policy should mask: {output}");
    // Map keys are deliberately preserved; only values redact.
    assert!(output.contains('1'), "map key should survive: {output}");
    // The IP policy masks the leading octets; no raw address may survive on any
    // of the bare, map-value, or set-element routes.
    assert!(!output.contains(IP_CANARY));
    assert!(!output.contains(IP_MAP_CANARY));
    assert!(!output.contains(IP_SET_CANARY));
}

#[cfg(all(feature = "ip-address", feature = "slog"))]
#[test]
fn ip_policy_bare_map_and_set_consuming_slog_json_redacts_without_clone() {
    let rendered = match ip_collection_event()
        .slog_redacted_json()
        .to_redacted_output()
    {
        RedactedOutput::Json(output) => output.to_string(),
        other => panic!("slog JSON adapter should produce JSON output, got {other:?}"),
    };
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

#[derive(Clone, Sensitive)]
struct SharedOwnerEvent {
    #[sensitive(Secret)]
    secret: std::sync::Arc<RefCell<String>>,
}

#[derive(Clone, Sensitive)]
struct RcOwnerEvent {
    #[sensitive(Secret)]
    secret: std::rc::Rc<RefCell<String>>,
}

const SHARED_OWNER_CANARY: &str = "round3-shared-owner-canary";

// `clippy::arc_with_non_send_sync` fires on the construction below, reporting
// exactly the point these tests exist to record: `Arc<RefCell<String>>` is not
// `Send + Sync` because `RefCell` is not `Sync`. That anti-pattern is the
// subject under test, not an oversight, so the lint is allowed here only.
#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn consuming_arc_refcell_still_panics_under_a_live_mutable_borrow() {
    let event = SharedOwnerEvent {
        secret: std::sync::Arc::new(RefCell::new(SHARED_OWNER_CANARY.to_owned())),
    };
    let _borrow = event.secret.borrow_mut();
    let result = catch_unwind(AssertUnwindSafe(|| event.clone().into_redacted_output()));
    assert!(
        result.is_err(),
        "Arc traversal must clone its referent, so a live mutable borrow panics"
    );
}

#[test]
fn consuming_rc_refcell_still_panics_under_a_live_mutable_borrow() {
    let event = RcOwnerEvent {
        secret: std::rc::Rc::new(RefCell::new(SHARED_OWNER_CANARY.to_owned())),
    };
    let _borrow = event.secret.borrow_mut();
    let result = catch_unwind(AssertUnwindSafe(|| event.clone().into_redacted_output()));
    assert!(
        result.is_err(),
        "Rc traversal must clone its referent, so a live mutable borrow panics"
    );
}

// The same shape is fine when nothing holds a borrow: the shape now compiles
// (the deleted hierarchy rejected it outright) and redacts correctly.
#[test]
#[allow(clippy::arc_with_non_send_sync)] // Same anti-pattern under test; see above.
fn consuming_arc_refcell_redacts_when_unborrowed() {
    let event = SharedOwnerEvent {
        secret: std::sync::Arc::new(RefCell::new(SHARED_OWNER_CANARY.to_owned())),
    };
    let output = match event.into_redacted_output() {
        RedactedOutput::Text(output) => output,
        other => panic!("structural output should be text, got {other:?}"),
    };
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
    let event = redactable_test_fixtures::PublicRedactedEvent::new(
        "e0446-token-canary",
        "e0446-note-canary",
    );
    assert_eq!(event.detail_note(), "e0446-note-canary");

    let redacted = event.redact();
    assert_eq!(redacted.token, "[REDACTED]");
    // The unannotated private field is walked, not redacted.
    assert_eq!(redacted.detail_note(), "e0446-note-canary");
}

#[test]
fn public_struct_with_private_field_type_redacts_through_consuming_output() {
    let event = redactable_test_fixtures::PublicRedactedEvent::new(
        "e0446-token-canary",
        "e0446-note-canary",
    );
    let output = match event.into_redacted_output() {
        RedactedOutput::Text(output) => output,
        other => panic!("structural output should be text, got {other:?}"),
    };
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains("e0446-token-canary"));
}
