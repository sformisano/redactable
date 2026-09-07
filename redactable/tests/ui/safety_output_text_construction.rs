use redactable::{RedactedOutput, ToRedactedOutput, UncheckedRedactedSummary};
fn main() {
    // Migrate selected summaries through UncheckedRedactedSummary::new(...).
    let _ = RedactedOutput::Text(String::from("raw"));
    let _ = RedactedOutput::text(String::from("raw"));
    let _: RedactedOutput = String::from("raw").into();
    let declared = UncheckedRedactedSummary::new(String::from("declared")).to_redacted_output();
    let _ = RedactedOutput {
        representation: declared.representation,
    };
    let _ = UncheckedRedactedSummary::new(String::from("declared")).to_redacted_output();
}
