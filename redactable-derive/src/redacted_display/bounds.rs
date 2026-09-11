//! Collects complete-field predicates for the selected formatting route.

use syn::WherePredicate;

use super::model::{FieldInfo, FormatMode, FormattingRoute};
use crate::{
    generics::{
        push_debug_predicate, push_direct_marker_debug_formatting_predicates,
        push_direct_marker_display_formatting_predicates, push_display_predicate,
        push_generated_policy_debug_formatting_predicate,
        push_generated_policy_display_formatting_predicate,
        push_legacy_policy_debug_formatting_predicates,
        push_legacy_policy_display_formatting_predicates, push_policy_debug_formatting_predicate,
        push_policy_display_formatting_predicate, push_redacted_display_predicate,
    },
    strategy::Strategy,
};

pub(super) fn collect_bounds(
    field: &FieldInfo<'_>,
    mode: FormatMode,
    display_generics: &mut Vec<WherePredicate>,
    debug_generics: &mut Vec<WherePredicate>,
    policy_ref_generics: &mut Vec<WherePredicate>,
    nested_generics: &mut Vec<WherePredicate>,
) {
    if field.recursive_bound_override && field.formatting_route != FormattingRoute::Legacy {
        return;
    }
    let display = mode != FormatMode::Debug;
    let debug = mode != FormatMode::Display;
    match &field.strategy {
        Strategy::WalkDefault => push_redacted_display_predicate(nested_generics, field.ty),
        Strategy::NotSensitive => {
            if display {
                push_display_predicate(display_generics, field.ty);
            }
            if debug {
                push_debug_predicate(debug_generics, field.ty);
            }
        }
        Strategy::Policy(policy) => match field.formatting_route {
            FormattingRoute::Legacy => {
                if display {
                    push_legacy_policy_display_formatting_predicates(
                        policy_ref_generics,
                        field.ty,
                        policy,
                    );
                }
                if debug {
                    push_legacy_policy_debug_formatting_predicates(
                        policy_ref_generics,
                        field.ty,
                        policy,
                    );
                }
            }
            FormattingRoute::Declared => {
                if display {
                    push_generated_policy_display_formatting_predicate(
                        policy_ref_generics,
                        field.ty,
                        policy,
                    );
                }
                if debug {
                    push_generated_policy_debug_formatting_predicate(
                        policy_ref_generics,
                        field.ty,
                        policy,
                    );
                }
            }
            FormattingRoute::DirectMarker => {
                if display {
                    push_direct_marker_display_formatting_predicates(policy_ref_generics, field.ty);
                    push_policy_display_formatting_predicate(policy_ref_generics, field.ty, policy);
                }
                if debug {
                    push_direct_marker_debug_formatting_predicates(policy_ref_generics, field.ty);
                    push_policy_debug_formatting_predicate(policy_ref_generics, field.ty, policy);
                }
            }
            FormattingRoute::Nominal => {}
        },
    }
}
