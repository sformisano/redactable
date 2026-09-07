use redactable::{RedactedJson, RedactedOutput};
fn main() {
    let raw = serde_json::json!({"raw":true});
    // Migrate reviewed public projections through value.not_sensitive_json().
    let _ = RedactedOutput::Json(raw.clone());
    let _ = RedactedOutput::json(raw.clone());
    let _: RedactedOutput = raw.clone().into();
    let _ = RedactedJson::new(raw.clone());
    let _: RedactedOutput = serde_json::from_str("{\"raw\":true}").unwrap();
    let _ = redactable::__private::generated_redacted_json(raw.clone());
}
