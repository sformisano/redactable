use redactable::{NotSensitiveJsonExt, RedactedOutputView, ToRedactedOutput};

fn main() {
    let raw = serde_json::json!({"public": true});
    let output = raw.not_sensitive_json().to_redacted_output();
    if let RedactedOutputView::Json(value) = output.view() {
        value["public"] = false.into();
    }
}
