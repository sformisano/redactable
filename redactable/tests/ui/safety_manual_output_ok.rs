use redactable::__private::DeclaredFormatting;
use redactable::{
    NotSensitiveDebug, NotSensitiveDisplay, RedactableWithFormatter, RedactedOutput,
    RedactedOutputView, SensitiveDisplay, ToRedactedOutput, UncheckedRedactedSummary,
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
impl ToRedactedOutput for Manual {
    fn to_redacted_output(&self) -> RedactedOutput {
        UncheckedRedactedSummary::new("SELECTED".into()).to_redacted_output()
    }
}
fn sink<T: ToRedactedOutput>(value: &T) -> RedactedOutput {
    value.to_redacted_output()
}
fn main() {
    assert_eq!(
        Holder { field: Manual }.redacted_display().to_string(),
        "MANUAL"
    );
    assert_eq!(sink(&Manual).view(), RedactedOutputView::Text("SELECTED"));
    assert_eq!(
        sink(&UncheckedRedactedSummary::new(String::new())).view(),
        RedactedOutputView::Text("")
    );
    let _ = sink(&NotSensitiveDisplay("public"));
    let _ = sink(&NotSensitiveDebug(Error::other("public")));
    #[cfg(feature = "json")]
    {
        use redactable::NotSensitiveJsonExt;
        let _ = sink(&serde_json::json!({"public":true}).not_sensitive_json());
    }
}
