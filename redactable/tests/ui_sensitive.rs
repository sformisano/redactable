mod sensitive {
    #[test]
    fn accepts_generated_internal_name_collisions() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/derive_generated_internals_ok.rs");
        t.pass("tests/ui/followup_generated_definition_scope_ok.rs");
        t.pass("tests/ui/followup_generated_identifier_collisions_ok.rs");
    }

    #[test]
    fn accepts_qualified_primitive_policy_fields() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/qualified_primitive_policy_ok.rs");
    }

    #[test]
    fn accepts_complete_field_type_bounds() {
        let t = trybuild::TestCases::new();
        if cfg!(feature = "slog") {
            t.pass("tests/ui/phase01_complete_type_bounds_slog_ok.rs");
        } else {
            t.pass("tests/ui/phase01_complete_type_bounds_ok.rs");
        }
    }

    #[test]
    fn accepts_generic_cell_complete_type_bound() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/phase01_generic_cell_complete_type_bound_ok.rs");
    }

    #[test]
    fn rejects_user_phantom_data_without_traversal() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/phase01_user_phantom_data_no_traversal.rs");
    }

    #[test]
    fn accepts_empty_enums() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/sensitive_empty_enums_ok.rs");
    }

    #[test]
    fn accepts_genuine_generic_dual_pair() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/sensitive_dual_generic_ok.rs");
    }

    #[test]
    fn rejects_nonzero_policy_annotation() {
        let t = trybuild::TestCases::new();
        if cfg!(feature = "slog") {
            t.compile_fail("tests/ui/sensitive_nonzero_secret_rejected_slog.rs");
        } else {
            t.compile_fail("tests/ui/sensitive_nonzero_secret_rejected.rs");
        }
    }

    #[test]
    fn nonzero_support_is_resolved_by_type_identity() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/sensitive_nonzero_type_identity_ok.rs");
    }

    #[test]
    fn generated_code_works_without_the_implicit_prelude() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/sensitive_no_implicit_prelude_ok.rs");
    }

    #[test]
    fn clone_logging_keeps_refcell_api_available() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/sensitive_not_sensitive_clone_safe_ok.rs");
        t.pass("tests/ui/sensitive_not_sensitive_refcell_rejected.rs");
        if cfg!(feature = "slog") {
            t.pass("tests/ui/sensitive_not_sensitive_refcell_slog_rejected.rs");
        }
    }

    // The removed owned-capability hierarchy emitted the derived type's field
    // types into a public associated type, so a `pub` container holding a
    // private field type failed with `E0446: private type ... in public
    // interface`. This pass case pins that the derive no longer leaks field
    // visibility.
    #[test]
    fn accepts_public_struct_with_private_field_type() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/sensitive_private_field_type_public_struct_ok.rs");
    }

    #[test]
    fn rejects_scalar_non_secret_policy_annotation() {
        let t = trybuild::TestCases::new();
        if cfg!(feature = "slog") {
            t.compile_fail("tests/ui/sensitive_scalar_non_secret_rejected_slog.rs");
        } else {
            t.compile_fail("tests/ui/sensitive_scalar_non_secret_rejected.rs");
        }
    }

    #[test]
    fn rejects_bare_sensitive_attribute() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/sensitive_bare_sensitive_rejected.rs");
    }

    #[test]
    fn rejects_ip_address_containers_with_targeted_message() {
        let t = trybuild::TestCases::new();
        if cfg!(feature = "slog") {
            t.compile_fail("tests/ui/sensitive_ip_container_rejected_slog.rs");
            t.compile_fail("tests/ui/sensitive_ip_alias_container_rejected_slog.rs");
        } else {
            t.compile_fail("tests/ui/sensitive_ip_container_rejected.rs");
            t.compile_fail("tests/ui/sensitive_ip_alias_container_rejected.rs");
        }
    }

    #[test]
    fn rejects_legacy_ip_policy_bypasses() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/legacy_ip_policy_bypasses_rejected.rs");
    }

    #[test]
    fn rejects_union() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/sensitive_union_rejected.rs");
    }

    #[test]
    fn rejects_variant_level_attribute() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/sensitive_variant_attr_rejected.rs");
        t.compile_fail("tests/ui/sensitive_variant_not_sensitive_rejected.rs");
    }

    #[test]
    fn rejects_field_only_helpers_outside_fields() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/sensitive_container_not_sensitive_rejected.rs");
        t.compile_fail("tests/ui/sensitive_display_container_redactable_rejected.rs");
        t.compile_fail("tests/ui/sensitive_dual_variant_redactable_rejected.rs");
    }

    #[test]
    fn rejects_dual_without_sensitive_display() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/sensitive_dual_without_display_rejected.rs");
        t.compile_fail("tests/ui/sensitive_dual_hygienic_witness_forgery_rejected.rs");
    }

    #[test]
    fn rejects_display_only_legacy_formatting_option() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/sensitive_legacy_formatting_rejected.rs");
    }
}
