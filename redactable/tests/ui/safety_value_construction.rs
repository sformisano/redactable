use redactable::{BypassJsonRedaction, BypassTextRedaction, RedactedValue, ToRedacted};
fn main() {
    let raw = serde_json::json!({"raw": true});
    // No public variants and no public constructors.
    let _ = RedactedValue::Text(String::from("raw"));
    let _ = RedactedValue::Json(raw.clone());
    let _ = RedactedValue::text(String::from("raw"));
    let _ = RedactedValue::json(raw.clone());
    let _ = RedactedValue::from_text(String::from("raw"));
    // No conversion into the value from either representation.
    let _: RedactedValue = String::from("raw").into();
    let _: RedactedValue = raw.clone().into();
    let _: RedactedValue = serde_json::from_str("{\"raw\":true}").unwrap();
    // No field access and no view.
    let declared = BypassTextRedaction(String::from("declared")).to_redacted();
    let _ = declared.text;
    let _ = declared.json;
    let selected = BypassJsonRedaction(&raw).to_redacted();
    let _ = selected.view();
    let _ = selected.view_mut();
}
