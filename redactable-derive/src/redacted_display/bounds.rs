//! Conditional formatting bounds for explicitly public template fields.

use syn::WherePredicate;

use super::model::{FieldInfo, FormatMode};
use crate::{
    generics::{push_debug_predicate, push_display_predicate},
    strategy::Strategy,
};

pub(super) fn collect_bounds(
    field: &FieldInfo<'_>,
    mode: FormatMode,
    predicates: &mut Vec<WherePredicate>,
) {
    if field.recursive_bound_override || !matches!(field.strategy, Strategy::NotSensitive) {
        return;
    }
    // Formatting borrows the field. A formatter on &T does not imply one on T,
    // so these complete-type bounds independently restrict impl availability.
    match mode {
        FormatMode::Display => push_display_predicate(predicates, field.ty),
        FormatMode::Debug => push_debug_predicate(predicates, field.ty),
    }
}
