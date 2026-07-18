use redactable::{NotSensitiveDisplay, RedactableWithFormatter};

// Test basic struct with Display impl
#[derive(Clone, NotSensitiveDisplay)]
struct PublicStatus {
    code: u32,
    message: String,
}

impl std::fmt::Display for PublicStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

#[test]
fn generates_redactable_display_for_struct() {
    let status = PublicStatus {
        code: 200,
        message: "OK".into(),
    };

    // RedactableWithFormatter delegates to Display
    let display = format!("{}", status.redacted_display());
    assert_eq!(display, "200: OK");
}

// Test enum with Display impl
#[derive(Clone, NotSensitiveDisplay)]
enum RetryDecision {
    Retry { delay_ms: u64 },
    Abort,
}

impl std::fmt::Display for RetryDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retry { delay_ms } => write!(f, "Retry after {}ms", delay_ms),
            Self::Abort => write!(f, "Abort"),
        }
    }
}

#[test]
fn generates_redactable_display_for_enum() {
    let retry = RetryDecision::Retry { delay_ms: 1000 };
    let display = format!("{}", retry.redacted_display());
    assert_eq!(display, "Retry after 1000ms");

    let abort = RetryDecision::Abort;
    let display = format!("{}", abort.redacted_display());
    assert_eq!(display, "Abort");
}

// Test unit struct
#[derive(Clone, NotSensitiveDisplay)]
struct Marker;

impl std::fmt::Display for Marker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Marker")
    }
}

#[test]
fn generates_redactable_display_for_unit_struct() {
    let marker = Marker;
    let display = format!("{}", marker.redacted_display());
    assert_eq!(display, "Marker");
}

// Test tuple struct
#[derive(Clone, NotSensitiveDisplay)]
struct StatusCode(u16);

impl std::fmt::Display for StatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Status({})", self.0)
    }
}

#[test]
fn generates_redactable_display_for_tuple_struct() {
    let code = StatusCode(404);
    let display = format!("{}", code.redacted_display());
    assert_eq!(display, "Status(404)");
}

// Test that NotSensitiveDisplay does not conflict with #[derive(Debug)]
#[derive(Clone, Debug, NotSensitiveDisplay)]
struct WithOwnDebug {
    value: String,
}

impl std::fmt::Display for WithOwnDebug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WithOwnDebug({})", self.value)
    }
}

#[test]
fn derive_debug_works_alongside_not_sensitive_display() {
    let value = WithOwnDebug {
        value: "test".into(),
    };

    // Display via RedactableWithFormatter
    let display = format!("{}", value.redacted_display());
    assert_eq!(display, "WithOwnDebug(test)");

    // Debug uses our own impl (from derive(Debug))
    let debug = format!("{:?}", value);
    assert_eq!(debug, "WithOwnDebug { value: \"test\" }");
}

// Test generic type with Display bound
#[derive(Clone, NotSensitiveDisplay)]
struct Wrapper<T> {
    inner: T,
}

impl<T: std::fmt::Display> std::fmt::Display for Wrapper<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Wrapper({})", self.inner)
    }
}

#[test]
fn works_with_generic_types() {
    let wrapper = Wrapper { inner: 42 };
    let display = format!("{}", wrapper.redacted_display());
    assert_eq!(display, "Wrapper(42)");
}

// Test that NotSensitiveDisplay types can be used inside Sensitive containers
// This works because NotSensitiveDisplay also generates RedactableWithMapper
mod inside_sensitive_container {
    use redactable::{NotSensitiveDisplay, Redactable, RedactableWithFormatter, Secret, Sensitive};

    // A simple enum with NotSensitiveDisplay that has a Display impl
    #[derive(Clone, NotSensitiveDisplay, PartialEq)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    enum RetryDecision {
        Retry,
        Abort,
    }

    impl std::fmt::Debug for RetryDecision {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Retry => write!(f, "RetryDecision::Retry"),
                Self::Abort => write!(f, "RetryDecision::Abort"),
            }
        }
    }

    impl std::fmt::Display for RetryDecision {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Retry => write!(f, "Retry"),
                Self::Abort => write!(f, "Abort"),
            }
        }
    }

    #[test]
    fn not_sensitive_display_type_in_sensitive_struct() {
        // This test proves NotSensitiveDisplay generates RedactableWithMapper
        // If it didn't, this wouldn't compile
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct JobEvent {
            #[sensitive(Secret)]
            api_key: String,
            retry_decision: RetryDecision,
        }

        let event = JobEvent {
            api_key: "sk_live_secret123".into(),
            retry_decision: RetryDecision::Retry,
        };

        let redacted = event.redact();

        // api_key should be redacted
        assert_eq!(redacted.api_key, "[REDACTED]");
        // retry_decision should pass through unchanged (not sensitive)
        assert_eq!(redacted.retry_decision, RetryDecision::Retry);
    }

    #[test]
    fn not_sensitive_display_struct_in_sensitive_struct() {
        #[derive(Clone, NotSensitiveDisplay, PartialEq)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct StatusInfo {
            code: u32,
            message: String,
        }

        impl std::fmt::Debug for StatusInfo {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("StatusInfo")
                    .field("code", &self.code)
                    .field("message", &self.message)
                    .finish()
            }
        }

        impl std::fmt::Display for StatusInfo {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}: {}", self.code, self.message)
            }
        }

        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct ApiResponse {
            #[sensitive(Secret)]
            auth_token: String,
            status: StatusInfo,
        }

        let response = ApiResponse {
            auth_token: "bearer_secret_token".into(),
            status: StatusInfo {
                code: 200,
                message: "OK".into(),
            },
        };

        let redacted = response.redact();

        assert_eq!(redacted.auth_token, "[REDACTED]");
        assert_eq!(
            redacted.status,
            StatusInfo {
                code: 200,
                message: "OK".into()
            }
        );
    }

    #[test]
    fn not_sensitive_display_in_vec_inside_sensitive() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct BatchJob {
            #[sensitive(Secret)]
            credentials: String,
            decisions: Vec<RetryDecision>,
        }

        let job = BatchJob {
            credentials: "secret_creds".into(),
            decisions: vec![
                RetryDecision::Retry,
                RetryDecision::Abort,
                RetryDecision::Retry,
            ],
        };

        let redacted = job.redact();

        assert_eq!(redacted.credentials, "[REDACTED]");
        assert_eq!(redacted.decisions.len(), 3);
        assert_eq!(redacted.decisions[0], RetryDecision::Retry);
        assert_eq!(redacted.decisions[1], RetryDecision::Abort);
        assert_eq!(redacted.decisions[2], RetryDecision::Retry);
    }

    #[test]
    fn not_sensitive_display_still_works_for_display() {
        // Verify RedactableWithFormatter still works correctly
        let decision = RetryDecision::Abort;
        let display = format!("{}", decision.redacted_display());
        assert_eq!(display, "Abort");
    }
}
