use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

use crate::log_redacted;
use redactable::{BypassDebugRedaction, BypassDisplayRedaction, BypassRedactionMarker};

#[test]
fn debug_wrapper_uses_debug_formatting() {
    #[derive(Debug)]
    #[allow(dead_code)]
    struct DebugOnly {
        id: u64,
    }

    let value = DebugOnly { id: 7 };
    let redacted = log_redacted(&BypassDebugRedaction(&value));
    assert_eq!(redacted.text(), "DebugOnly { id: 7 }");
}

#[test]
fn generic_wrapper_accepts_types_without_display_or_debug() {
    struct NoTraits {
        id: u64,
    }

    let value = NoTraits { id: 7 };
    let wrapped = BypassRedactionMarker(&value);
    assert_eq!(wrapped.inner().id, 7);
}

#[test]
fn the_marker_borrows_so_the_value_remains_usable() {
    // This is the main use case: log a value and continue using it
    let error_msg = "connection failed".to_string();

    // Use in logging context (simulated)
    let _logged = format!("{}", BypassRedactionMarker(&error_msg));

    // Value is still usable after - it would not be if the wrapper consumed it
    assert_eq!(error_msg, "connection failed");

    // Same for display/debug variants
    let _display = log_redacted(&BypassDisplayRedaction(&error_msg));
    let _debug = log_redacted(&BypassDebugRedaction(&error_msg));
    assert_eq!(error_msg, "connection failed");
}

#[test]
fn display_wrapper_uses_display_and_debug_wrapper_uses_debug() {
    struct FormatType(u64);

    impl Display for FormatType {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            write!(f, "display-{}", self.0)
        }
    }

    impl Debug for FormatType {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            write!(f, "debug-{}", self.0)
        }
    }

    let value = FormatType(1);
    let display_output = log_redacted(&BypassDisplayRedaction(&value));
    assert_eq!(display_output.text(), "display-1");

    let debug_output = log_redacted(&BypassDebugRedaction(&value));
    assert_eq!(debug_output.text(), "debug-1");

    let display_wrapper = BypassDisplayRedaction(&value);
    assert_eq!(format!("{display_wrapper:?}"), "display-1");

    let generic_wrapper = BypassRedactionMarker(&value);
    assert_eq!(format!("{generic_wrapper}"), "display-1");
    assert_eq!(format!("{generic_wrapper:?}"), "debug-1");
}
