//! Declaration bounds for borrowed, policy-specific formatting.

use std::fmt::{Formatter, Result as FmtResult};

use crate::{
    __private::{PolicyKindDebugFormatting, PolicyKindDisplayFormatting},
    RedactionPolicy,
};

/// A field that supports a display placeholder under policy `P`.
///
/// Declare this bound on generic fields used as `{value}` by `SensitiveDisplay`.
/// It borrows the field and does not require `Clone` or structural redaction.
/// Every `#[sensitive(P)]` template field is formatted through it, so a
/// concrete field type that does not implement it is rejected at the derive.
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be formatted with `{{}}` under policy `{P}`",
    label = "this policy field has no borrowed display formatting",
    note = "text policies format `String`, `Cow<str>`, `&str`, `serde_json::Value`, `SensitiveValue<T, P>`, and supported containers of these; `Secret` also formats scalars and `IpAddress` formats bare typed IP values",
    note = "for a custom leaf, implement `redactable::PolicyFormat`; for a generic field, declare `T: PolicyDisplay<P>`"
)]
pub trait PolicyDisplay<P: RedactionPolicy> {
    /// Formats this field using policy `P`.
    fn fmt_policy_display(&self, formatter: &mut Formatter<'_>) -> FmtResult;
}

/// A field that supports a debug placeholder under policy `P`.
///
/// Declare this bound on generic fields used as `{value:?}` by `SensitiveDisplay`.
/// Templates using both modes require both this trait and [`PolicyDisplay`].
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be formatted with `{{:?}}` under policy `{P}`",
    label = "this policy field has no borrowed debug formatting",
    note = "text policies format `String`, `Cow<str>`, `&str`, `serde_json::Value`, `SensitiveValue<T, P>`, and supported containers of these; `Secret` also formats scalars and `IpAddress` formats bare typed IP values",
    note = "for a custom leaf, implement `redactable::PolicyFormat`; for a generic field, declare `T: PolicyDebug<P>`"
)]
pub trait PolicyDebug<P: RedactionPolicy> {
    /// Debug-formats this field using policy `P`.
    fn fmt_policy_debug(&self, formatter: &mut Formatter<'_>) -> FmtResult;
}

impl<P, T: ?Sized> PolicyDisplay<P> for T
where
    P: RedactionPolicy,
    P::Kind: PolicyKindDisplayFormatting<P, T>,
{
    fn fmt_policy_display(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        P::Kind::fmt_display(self, formatter)
    }
}

impl<P, T: ?Sized> PolicyDebug<P> for T
where
    P: RedactionPolicy,
    P::Kind: PolicyKindDebugFormatting<P, T>,
{
    fn fmt_policy_debug(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        P::Kind::fmt_debug(self, formatter)
    }
}
