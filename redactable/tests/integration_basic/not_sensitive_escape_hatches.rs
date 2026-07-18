use super::*;

#[test]
fn debug_wrapper_uses_debug_formatting() {
    #[derive(Debug)]
    #[allow(dead_code)]
    struct DebugOnly {
        id: u64,
    }

    let value = DebugOnly { id: 7 };
    let redacted = log_redacted(&value.not_sensitive_debug());
    assert_eq!(
        redacted,
        RedactedOutput::Text("DebugOnly { id: 7 }".to_string())
    );
}

#[test]
fn generic_wrapper_accepts_types_without_display_or_debug() {
    struct NoTraits {
        id: u64,
    }

    let value = NoTraits { id: 7 };
    let wrapped = value.not_sensitive();
    assert_eq!(wrapped.inner().id, 7);
}

#[test]
fn not_sensitive_borrows_so_value_remains_usable() {
    // This is the main use case: log a value and continue using it
    let error_msg = "connection failed".to_string();

    // Use in logging context (simulated)
    let _logged = format!("{}", error_msg.not_sensitive());

    // Value is still usable after - this would fail if not_sensitive() consumed
    assert_eq!(error_msg, "connection failed");

    // Same for display/debug variants
    let _display = log_redacted(&error_msg.not_sensitive_display());
    let _debug = log_redacted(&error_msg.not_sensitive_debug());
    assert_eq!(error_msg, "connection failed");
}

#[test]
fn display_wrapper_uses_display_and_debug_wrapper_uses_debug() {
    struct FormatType(u64);

    impl std::fmt::Display for FormatType {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "display-{}", self.0)
        }
    }

    impl std::fmt::Debug for FormatType {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "debug-{}", self.0)
        }
    }

    let value = FormatType(1);
    let display_output = log_redacted(&value.not_sensitive_display());
    assert_eq!(
        display_output,
        RedactedOutput::Text("display-1".to_string())
    );

    let debug_output = log_redacted(&value.not_sensitive_debug());
    assert_eq!(debug_output, RedactedOutput::Text("debug-1".to_string()));

    let display_wrapper = value.not_sensitive_display();
    assert_eq!(format!("{display_wrapper:?}"), "display-1");

    let generic_wrapper = value.not_sensitive();
    assert_eq!(format!("{generic_wrapper}"), "display-1");
    assert_eq!(format!("{generic_wrapper:?}"), "debug-1");
}
