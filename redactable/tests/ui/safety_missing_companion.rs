use redactable::{RedactableWithFormatter, SensitiveDisplay};
use std::fmt::{Formatter, Result as FmtResult};
struct Manual;
impl RedactableWithFormatter for Manual {
    fn fmt_redacted(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("SELECTED")
    }
}
#[derive(SensitiveDisplay)]
#[error("{manual}")]
struct Holder {
    manual: Manual,
}
fn main() {}
