use redactable::{BypassDisplayRedaction, RedactedOutputView, ToRedacted};
fn main() {
    let value = BypassDisplayRedaction(String::from("declared")).to_redacted();
    match value.view() {
        RedactedOutputView::Text(_) => {}
        _ => {}
    }
}
