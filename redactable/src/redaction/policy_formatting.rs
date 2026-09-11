//! Declaration bounds for borrowed, policy-specific formatting.

use std::fmt::{Formatter, Result as FmtResult};

use crate::{
    __private::{GeneratedPolicyKindDebugFormatting, GeneratedPolicyKindDisplayFormatting},
    RedactionPolicy,
};

/// A field that supports a display placeholder under policy `P`.
///
/// Declare this bound on generic fields used as `{value}` by `SensitiveDisplay`.
/// It borrows the field and does not require `Clone` or structural redaction.
pub trait PolicyDisplay<P: RedactionPolicy> {
    /// Formats this field using policy `P`.
    fn fmt_policy_display(&self, formatter: &mut Formatter<'_>) -> FmtResult;
}

/// A field that supports a debug placeholder under policy `P`.
///
/// Declare this bound on generic fields used as `{value:?}` by `SensitiveDisplay`.
/// Templates using both modes require both this trait and [`PolicyDisplay`].
pub trait PolicyDebug<P: RedactionPolicy> {
    /// Debug-formats this field using policy `P`.
    fn fmt_policy_debug(&self, formatter: &mut Formatter<'_>) -> FmtResult;
}

impl<P, T: ?Sized> PolicyDisplay<P> for T
where
    P: RedactionPolicy,
    P::Kind: GeneratedPolicyKindDisplayFormatting<P, T>,
{
    fn fmt_policy_display(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        P::Kind::fmt_generated_display(self, formatter)
    }
}

impl<P, T: ?Sized> PolicyDebug<P> for T
where
    P: RedactionPolicy,
    P::Kind: GeneratedPolicyKindDebugFormatting<P, T>,
{
    fn fmt_policy_debug(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        P::Kind::fmt_generated_debug(self, formatter)
    }
}
