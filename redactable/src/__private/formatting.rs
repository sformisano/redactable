//! The borrowed projection generated templates format policy fields through.

use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::marker::PhantomData;

use crate::{PolicyDebug, PolicyDisplay, RedactionPolicy};

/// Borrowed formatter for one `#[sensitive(P)]` template field.
///
/// `Display` requires [`PolicyDisplay<P>`] and `Debug` requires
/// [`PolicyDebug<P>`], so a template only compiles when the field declares the
/// formatting it uses.
#[doc(hidden)]
pub struct PolicyFormattingRef<'a, P, T: ?Sized> {
    value: &'a T,
    policy: PhantomData<P>,
}

/// Borrows a field for policy formatting without cloning or consuming it.
#[doc(hidden)]
pub fn policy_formatting_ref<P, T: ?Sized>(value: &T) -> PolicyFormattingRef<'_, P, T> {
    PolicyFormattingRef {
        value,
        policy: PhantomData,
    }
}

impl<P: RedactionPolicy, T: PolicyDisplay<P> + ?Sized> Display for PolicyFormattingRef<'_, P, T> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        self.value.fmt_policy_display(formatter)
    }
}

impl<P: RedactionPolicy, T: PolicyDebug<P> + ?Sized> Debug for PolicyFormattingRef<'_, P, T> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        self.value.fmt_policy_debug(formatter)
    }
}
