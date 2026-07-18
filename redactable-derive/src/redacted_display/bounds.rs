//! Generic-bound construction for redacted `Display` impls.
//!
//! Computes the `where` predicates of the generated implementation from each
//! field's strategy: direct marker formatting bounds, legacy policy
//! formatting bounds, generated policy formatting bounds, or plain
//! `Display`/`Debug` bounds, with recursive containers routed through the
//! recursive-policy-kinds. Bounds are chosen per field and deduplicated so
//! the generated impl carries exactly the bounds its expansion needs — no
//! more, no less.

use crate::{
    generics::{
        OwnerTypeParameterUsage, owner_type_parameter_usage, policy_is_owner_type_parameter,
        push_debug_predicate, push_direct_marker_debug_formatting_predicates,
        push_direct_marker_display_formatting_predicates, push_display_predicate,
        push_generated_policy_debug_formatting_predicate,
        push_generated_policy_display_formatting_predicate,
        push_legacy_policy_debug_formatting_predicates,
        push_legacy_policy_display_formatting_predicates, push_policy_debug_formatting_predicate,
        push_policy_display_formatting_predicate, push_redacted_display_predicate,
        references_explicit_policy_applicable_ref,
    },
    strategy::Strategy,
};

use super::model::{FieldInfo, FormatMode};

#[allow(clippy::too_many_lines)]
pub(super) fn collect_bounds(
    field: &FieldInfo<'_>,
    mode: FormatMode,
    generics: &syn::Generics,
    display_generics: &mut Vec<syn::WherePredicate>,
    debug_generics: &mut Vec<syn::WherePredicate>,
    policy_ref_generics: &mut Vec<syn::WherePredicate>,
    nested_generics: &mut Vec<syn::WherePredicate>,
) {
    if let Strategy::Policy(policy) = &field.strategy
        && field.legacy_formatting_override
    {
        match mode {
            FormatMode::Display => {
                push_legacy_policy_display_formatting_predicates(
                    policy_ref_generics,
                    field.ty,
                    policy,
                );
            }
            FormatMode::Debug => {
                push_legacy_policy_debug_formatting_predicates(
                    policy_ref_generics,
                    field.ty,
                    policy,
                );
            }
            FormatMode::Both => {
                push_legacy_policy_display_formatting_predicates(
                    policy_ref_generics,
                    field.ty,
                    policy,
                );
                push_legacy_policy_debug_formatting_predicates(
                    policy_ref_generics,
                    field.ty,
                    policy,
                );
            }
        }
        return;
    }

    if field.recursive_bound_override {
        return;
    }

    match &field.strategy {
        Strategy::WalkDefault => {
            push_redacted_display_predicate(nested_generics, field.ty);
        }
        Strategy::NotSensitive => match mode {
            FormatMode::Display => push_display_predicate(display_generics, field.ty),
            FormatMode::Debug => push_debug_predicate(debug_generics, field.ty),
            FormatMode::Both => {
                push_display_predicate(display_generics, field.ty);
                push_debug_predicate(debug_generics, field.ty);
            }
        },
        Strategy::Policy(policy) => match owner_type_parameter_usage(generics, field.ty) {
            OwnerTypeParameterUsage::Bare | OwnerTypeParameterUsage::Composite
                if references_explicit_policy_applicable_ref(generics, field.ty) =>
            {
                match mode {
                    FormatMode::Display => {
                        push_direct_marker_display_formatting_predicates(
                            policy_ref_generics,
                            field.ty,
                        );
                        push_policy_display_formatting_predicate(
                            policy_ref_generics,
                            field.ty,
                            policy,
                        );
                    }
                    FormatMode::Debug => {
                        push_direct_marker_debug_formatting_predicates(
                            policy_ref_generics,
                            field.ty,
                        );
                        push_policy_debug_formatting_predicate(
                            policy_ref_generics,
                            field.ty,
                            policy,
                        );
                    }
                    FormatMode::Both => {
                        push_direct_marker_display_formatting_predicates(
                            policy_ref_generics,
                            field.ty,
                        );
                        push_direct_marker_debug_formatting_predicates(
                            policy_ref_generics,
                            field.ty,
                        );
                        push_policy_display_formatting_predicate(
                            policy_ref_generics,
                            field.ty,
                            policy,
                        );
                        push_policy_debug_formatting_predicate(
                            policy_ref_generics,
                            field.ty,
                            policy,
                        );
                    }
                }
            }
            OwnerTypeParameterUsage::Bare | OwnerTypeParameterUsage::Composite => match mode {
                FormatMode::Display => push_generated_policy_display_formatting_predicate(
                    policy_ref_generics,
                    field.ty,
                    policy,
                ),
                FormatMode::Debug => push_generated_policy_debug_formatting_predicate(
                    policy_ref_generics,
                    field.ty,
                    policy,
                ),
                FormatMode::Both => {
                    push_generated_policy_display_formatting_predicate(
                        policy_ref_generics,
                        field.ty,
                        policy,
                    );
                    push_generated_policy_debug_formatting_predicate(
                        policy_ref_generics,
                        field.ty,
                        policy,
                    );
                }
            },
            // The nominal probe in the generated expression lets rustc select
            // the concrete field capability after aliases and renamed imports
            // are resolved. Constrain that resolved kind-level capability;
            // classifying a concrete field from its Syn spelling makes aliases
            // observably different from the type they name.
            OwnerTypeParameterUsage::None
                if policy_is_owner_type_parameter(generics, policy)
                    && field.generated_formatting_override =>
            {
                match mode {
                    FormatMode::Display => push_generated_policy_display_formatting_predicate(
                        policy_ref_generics,
                        field.ty,
                        policy,
                    ),
                    FormatMode::Debug => push_generated_policy_debug_formatting_predicate(
                        policy_ref_generics,
                        field.ty,
                        policy,
                    ),
                    FormatMode::Both => {
                        push_generated_policy_display_formatting_predicate(
                            policy_ref_generics,
                            field.ty,
                            policy,
                        );
                        push_generated_policy_debug_formatting_predicate(
                            policy_ref_generics,
                            field.ty,
                            policy,
                        );
                    }
                }
            }
            OwnerTypeParameterUsage::None if policy_is_owner_type_parameter(generics, policy) => {
                match mode {
                    FormatMode::Display => push_policy_display_formatting_predicate(
                        policy_ref_generics,
                        field.ty,
                        policy,
                    ),
                    FormatMode::Debug => push_policy_debug_formatting_predicate(
                        policy_ref_generics,
                        field.ty,
                        policy,
                    ),
                    FormatMode::Both => {
                        push_policy_display_formatting_predicate(
                            policy_ref_generics,
                            field.ty,
                            policy,
                        );
                        push_policy_debug_formatting_predicate(
                            policy_ref_generics,
                            field.ty,
                            policy,
                        );
                    }
                }
            }
            OwnerTypeParameterUsage::None => {}
        },
    }
}
