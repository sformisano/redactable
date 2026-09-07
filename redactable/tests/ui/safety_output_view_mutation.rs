use redactable::{RedactedOutput, ToRedactedOutput, UncheckedRedactedSummary};
fn main() {
    let mut output = UncheckedRedactedSummary::new(String::from("declared")).to_redacted_output();
    let _ = output.view_mut();
    let _: RedactedOutput = output.view().into();
}
