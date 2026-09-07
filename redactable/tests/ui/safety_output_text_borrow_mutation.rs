use redactable::{RedactedOutputView, ToRedactedOutput, UncheckedRedactedSummary};

fn main() {
    let output = UncheckedRedactedSummary::new(String::from("declared")).to_redacted_output();
    if let RedactedOutputView::Text(text) = output.view() {
        text.make_ascii_uppercase();
    }
}
