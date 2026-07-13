mod sensitive {
    #[test]
    fn accepts_generated_internal_name_collisions() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/derive_generated_internals_ok.rs");
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
    fn rejects_nonzero_policy_annotation() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/sensitive_nonzero_secret_rejected.rs");
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
        } else {
            t.compile_fail("tests/ui/sensitive_ip_container_rejected.rs");
        }
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
    }

    #[test]
    fn rejects_dual_without_sensitive_display() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/sensitive_dual_without_display_rejected.rs");
    }
}
