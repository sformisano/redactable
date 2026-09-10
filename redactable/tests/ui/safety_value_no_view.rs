use redactable::{BypassTextRedaction, RedactedOutputView, ToRedacted};
fn main() {
    let value = BypassTextRedaction(String::from("declared")).to_redacted();
    match value.view() {
        RedactedOutputView::Text(_) => {}
        _ => {}
    }
}
