//! Both accessors always answer, whichever representation was built.

use redactable::{BypassJsonRedaction, BypassTextRedaction, ToRedacted};
use serde_json::json;

fn main() {
    let text = BypassTextRedaction(String::from("summary")).to_redacted();
    assert_eq!(text.text(), "summary");
    assert_eq!(text.json(), json!({"message": "summary"}));

    let empty = BypassTextRedaction(String::new()).to_redacted();
    assert_eq!(empty.text(), "");
    assert_eq!(empty.json(), json!({"message": ""}));

    let raw = json!({"public": true});
    let structured = BypassJsonRedaction(&raw).to_redacted();
    assert_eq!(structured.json(), raw);
    assert_eq!(structured.text(), "{\"public\":true}");
}
