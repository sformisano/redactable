use trybuild::TestCases;

#[test]
fn legacy_text_does_not_gain_direct_formatting_or_serde_traits() {
    TestCases::new().compile_fail("tests/ui/legacy_text_display_serde_rejected.rs");
}

#[cfg(all(feature = "slog", feature = "tracing"))]
#[test]
fn legacy_text_does_not_gain_logging_marker_traits() {
    TestCases::new().compile_fail("tests/ui/legacy_text_logging_markers_rejected.rs");
}
