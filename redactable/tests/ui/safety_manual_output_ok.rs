use redactable::__private::DeclaredFormatting as LegacyDeclaredFormatting;
use redactable::{
    BypassDebugRedaction, BypassDisplayRedaction, BypassJsonRedaction, DeclaredFormatting,
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
fn legacy_declared<T: LegacyDeclaredFormatting + ?Sized>(_: &T) {}
#[derive(SensitiveDisplay)]
#[error("{field}")]
struct Holder {
    field: Manual,
}
impl ToRedacted for Manual {
    fn to_redacted(&self) -> RedactedValue {
        BypassDisplayRedaction("SELECTED").to_redacted()
    }
}
fn sink<T: ToRedacted>(value: &T) -> RedactedValue {
    value.to_redacted()
}
fn main() {
    legacy_declared(&Manual);
    assert_eq!(
        Holder { field: Manual }.redacted_display().to_string(),
        "MANUAL"
    );
    assert_eq!(sink(&Manual).text(), "SELECTED");
    assert_eq!(sink(&BypassDisplayRedaction(String::new())).text(), "");
    let _ = sink(&BypassDisplayRedaction("public"));
    let _ = sink(&BypassDebugRedaction(Error::other("public")));
    let _ = sink(&BypassJsonRedaction(&serde_json::json!({"public":true})));
}
