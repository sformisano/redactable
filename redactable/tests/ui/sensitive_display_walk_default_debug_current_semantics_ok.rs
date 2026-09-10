use redactable::{NotSensitiveDisplay, RedactableWithFormatter, SensitiveDisplay};
use std::fmt::{Display, Formatter, Result as FmtResult};

// A default declared field uses its redacted formatter even for `:?`.
#[derive(SensitiveDisplay)]
#[error("value {value:?}")]
struct DebugTemplate {
    value: PublicText,
}

#[derive(NotSensitiveDisplay)]
struct PublicText(String);
impl Display for PublicText {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(&self.0)
    }
}

fn main() {
    let value = DebugTemplate {
        value: PublicText("plain".to_string()),
    };
    assert_eq!(value.redacted_display().to_string(), "value plain");
}
