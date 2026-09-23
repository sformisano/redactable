//! Collects complete-field predicates for the formatted fields of a template.

use syn::WherePredicate;

use super::model::{FieldInfo, FormatMode};
use crate::{
    generics::{
        push_debug_predicate, push_display_predicate, push_policy_debug_predicate,
        push_policy_display_predicate, push_redacted_display_predicate,
    },
    strategy::Strategy,
};

pub(super) fn collect_bounds(
    field: &FieldInfo<'_>,
    mode: FormatMode,
    predicates: &mut Vec<WherePredicate>,
) {
    if field.recursive_bound_override {
        return;
    }
    let display = mode != FormatMode::Debug;
    let debug = mode != FormatMode::Display;
    match &field.strategy {
        Strategy::WalkDefault => push_redacted_display_predicate(predicates, field.ty),
        Strategy::NotSensitive => {
            if display {
                push_display_predicate(predicates, field.ty);
            }
            if debug {
                push_debug_predicate(predicates, field.ty);
            }
        }
        Strategy::Policy(policy) => {
            if display {
                push_policy_display_predicate(predicates, field.ty, policy);
            }
            if debug {
                push_policy_debug_predicate(predicates, field.ty, policy);
            }
        }
    }
}
