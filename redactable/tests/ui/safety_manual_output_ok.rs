use redactable::__private::DeclaredFormatting;
use redactable::{
    BypassDebugRedaction, BypassDisplayRedaction, BypassJsonRedaction, BypassTextRedaction,
    RedactableWithFormatter, RedactedValue, SensitiveDisplay, ToRedacted,
};
use std::{
    fmt::{Formatter, Result as FmtResult},
    io::Error,
};
struct Manual;
impl RedactableWithFormatter for Manual {
    fn fmt_redacted(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("MANUAL")
    }
}
impl DeclaredFormatting for Manual {}
#[derive(SensitiveDisplay)]
#[error("{field}")]
struct Holder {
    field: Manual,
}
impl ToRedacted for Manual {
    fn to_redacted(&self) -> RedactedValue {
        BypassTextRedaction("SELECTED".into()).to_redacted()
    }
}
fn sink<T: ToRedacted>(value: &T) -> RedactedValue {
    value.to_redacted()
}
fn main() {
    assert_eq!(
        Holder { field: Manual }.redacted_display().to_string(),
        "MANUAL"
    );
    assert_eq!(sink(&Manual).text(), "SELECTED");
    assert_eq!(sink(&BypassTextRedaction(String::new())).text(), "");
    let _ = sink(&BypassDisplayRedaction("public"));
    let _ = sink(&BypassDebugRedaction(Error::other("public")));
    let _ = sink(&BypassJsonRedaction(&serde_json::json!({"public":true})));
}
