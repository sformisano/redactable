//! Every member of the Bypass family is constructed by tuple syntax and
//! reaches a `ToRedacted` sink; `BypassRedaction` only satisfies `Redactable`.

use redactable::{
    BypassDebugRedaction, BypassDisplayRedaction, BypassJsonRedaction, BypassRedaction,
    BypassRedactionMarker, BypassTextRedaction, Redactable, ToRedacted,
};

fn sink<T: ToRedacted>(value: &T) -> String {
    value.to_redacted().text()
}

fn redact_foreign<T: Redactable>(value: T) -> T {
    value.redact()
}

fn main() {
    let raw = serde_json::json!({"public": true});

    assert_eq!(sink(&BypassDisplayRedaction(42_u64)), "42");
    assert_eq!(
        sink(&BypassDebugRedaction(("public", 7_u64))),
        "(\"public\", 7)"
    );
    assert_eq!(sink(&BypassJsonRedaction(&raw)), "{\"public\":true}");
    assert_eq!(sink(&BypassTextRedaction(String::from("summary"))), "summary");
    assert_eq!(sink(&BypassTextRedaction(String::new())), "");

    // The two members whose fields were private now construct by tuple syntax.
    let json_bypass = BypassJsonRedaction(&raw);
    assert_eq!(json_bypass.0, &raw);
    assert_eq!(json_bypass.inner(), &raw);
    let text_bypass = BypassTextRedaction(String::from("named"));
    assert_eq!(text_bypass.0, "named");

    // A foreign value satisfies a `Redactable` bound without a producer.
    let foreign = redact_foreign(BypassRedaction(String::from("foreign")));
    assert_eq!(foreign.0, "foreign");

    // The marker carries a value with no formatting opinion at all.
    struct Opaque;
    let marker = BypassRedactionMarker(Opaque);
    let Opaque = marker.0;
}
