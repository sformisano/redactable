use super::*;

#[test]
fn emits_redacted_string() {
    #[derive(Debug)]
    struct NonSerializable {
        _detail: String,
    }

    impl RedactableWithMapper for NonSerializable {
        fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
            self
        }
    }

    #[derive(SensitiveDisplay)]
    enum LoginError {
        #[error("invalid login for {username} {password} {context:?} {attempts}")]
        InvalidCredentials {
            #[not_sensitive]
            username: String,
            #[sensitive(Secret)]
            password: String,
            #[not_sensitive]
            context: NonSerializable,
            #[sensitive(Secret)]
            attempts: usize,
        },
    }

    let err = LoginError::InvalidCredentials {
        username: "alice".into(),
        password: "hunter2".into(),
        context: NonSerializable {
            _detail: "remote".into(),
        },
        attempts: 3,
    };

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&err, "error", &mut serializer);

    if let Some(CapturedValue::Str(value)) = serializer.get("error") {
        assert_eq!(
            value,
            "invalid login for alice [REDACTED] NonSerializable { _detail: \"remote\" } 0"
        );
    } else {
        panic!("Expected Str value for 'error' key");
    }
}

#[test]
fn works_with_to_redacted_output() {
    #[derive(SensitiveDisplay)]
    enum LoginError {
        #[error("login failed for {user} {password}")]
        Invalid {
            #[not_sensitive]
            user: String,
            #[sensitive(Secret)]
            password: String,
        },
    }

    let err = LoginError::Invalid {
        user: "alice".into(),
        password: "hunter2".into(),
    };

    let output = log_redacted(&err);
    assert_eq!(
        output,
        RedactedOutput::Text("login failed for alice [REDACTED]".to_string())
    );
}

#[test]
fn handles_nested_errors() {
    #[derive(SensitiveDisplay)]
    enum InnerError {
        #[error("invalid api_key {api_key}")]
        InvalidApiKey {
            #[sensitive(Token)]
            api_key: String,
        },
    }

    impl fmt::Display for InnerError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.fmt_redacted(f)
        }
    }

    #[derive(SensitiveDisplay)]
    enum OuterError {
        #[error("user {user} {inner}")]
        Failure {
            #[not_sensitive]
            user: String,
            #[not_sensitive]
            inner: InnerError,
        },
    }

    let err = OuterError::Failure {
        user: "alice".into(),
        inner: InnerError::InvalidApiKey {
            api_key: "sk_live_abc123def456".into(),
        },
    };

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&err, "error", &mut serializer);

    if let Some(CapturedValue::Str(value)) = serializer.get("error") {
        assert_eq!(value, "user alice invalid api_key ****************f456");
    } else {
        panic!("Expected Str value for 'error' key");
    }
}

#[test]
fn handles_raw_opt_out() {
    #[derive(Debug)]
    struct RawContext;

    impl fmt::Display for RawContext {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("raw-context")
        }
    }

    #[derive(SensitiveDisplay)]
    enum RawError {
        #[error("context {context}")]
        Failure {
            #[not_sensitive]
            context: RawContext,
        },
    }

    let err = RawError::Failure {
        context: RawContext,
    };

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&err, "error", &mut serializer);

    if let Some(CapturedValue::Str(value)) = serializer.get("error") {
        assert_eq!(value, "context raw-context");
    } else {
        panic!("Expected Str value for 'error' key");
    }
}

#[test]
fn handles_doc_comment_template() {
    #[derive(SensitiveDisplay)]
    enum DocError {
        /// user {user} {secret}
        Variant {
            #[not_sensitive]
            user: String,
            #[sensitive(Secret)]
            secret: String,
        },
    }

    let err = DocError::Variant {
        user: "bob".into(),
        secret: "super_secret".into(),
    };

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&err, "error", &mut serializer);

    if let Some(CapturedValue::Str(value)) = serializer.get("error") {
        assert_eq!(value, "user bob [REDACTED]");
    } else {
        panic!("Expected Str value for 'error' key");
    }
}

#[test]
fn handles_debug_specifiers() {
    struct ModeValue;

    impl fmt::Display for ModeValue {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("display")
        }
    }

    impl fmt::Debug for ModeValue {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("debug")
        }
    }

    impl RedactableWithMapper for ModeValue {
        fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
            self
        }
    }

    #[derive(SensitiveDisplay)]
    enum LoginError {
        #[error("user {user} mode {mode} ctx {context:?} secret {password}")]
        Invalid {
            #[not_sensitive]
            user: String,
            #[not_sensitive]
            mode: ModeValue,
            #[not_sensitive]
            context: ModeValue,
            #[sensitive(Secret)]
            password: String,
        },
    }

    let err = LoginError::Invalid {
        user: "alice".into(),
        mode: ModeValue,
        context: ModeValue,
        password: "hunter2".into(),
    };

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&err, "error", &mut serializer);

    if let Some(CapturedValue::Str(value)) = serializer.get("error") {
        assert_eq!(value, "user alice mode display ctx debug secret [REDACTED]");
    } else {
        panic!("Expected Str value for 'error' key");
    }
}

#[test]
fn handles_positional_fields_with_error_attr() {
    #[derive(SensitiveDisplay)]
    enum PositionalError {
        #[error("code {0} secret {1}")]
        Invalid(#[not_sensitive] String, #[sensitive(Secret)] String),
    }

    let err = PositionalError::Invalid("E123".into(), "super_secret".into());

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&err, "error", &mut serializer);

    if let Some(CapturedValue::Str(value)) = serializer.get("error") {
        assert_eq!(value, "code E123 secret [REDACTED]");
    } else {
        panic!("Expected Str value for 'error' key");
    }
}

#[test]
fn handles_positional_fields_with_doc_comment() {
    #[derive(SensitiveDisplay)]
    enum DocPositionalError {
        /// code {0} name {1:?}
        Invalid(#[not_sensitive] String, #[sensitive(Pii)] String),
    }

    let err = DocPositionalError::Invalid("E42".into(), "John Smith".into());

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&err, "error", &mut serializer);

    if let Some(CapturedValue::Str(value)) = serializer.get("error") {
        assert_eq!(value, "code E42 name \"********th\"");
    } else {
        panic!("Expected Str value for 'error' key");
    }
}

#[test]
fn user_phantom_data_traverses_and_structured_slog_omits_canary() {
    const CANARY: &str = "phase01-user-phantom-canary-7f4c";

    #[derive(Clone, Serialize, Sensitive)]
    struct SecretLeaf {
        #[sensitive(Secret)]
        value: String,
    }

    #[derive(Clone, Serialize, Sensitive)]
    struct PhantomData<T> {
        value: T,
    }

    #[derive(Clone, Serialize, Sensitive)]
    struct Envelope {
        marker: PhantomData<SecretLeaf>,
    }

    let envelope = Envelope {
        marker: PhantomData {
            value: SecretLeaf {
                value: CANARY.into(),
            },
        },
    };
    let redacted = envelope.clone().redact();
    assert_eq!(redacted.marker.value.value, "[REDACTED]");
    assert!(!redacted.marker.value.value.contains(CANARY));

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&envelope, "envelope", &mut serializer);
    let captured = format!("{:?}", serializer.get("envelope"));
    assert!(captured.contains("[REDACTED]"));
    assert!(!captured.contains(CANARY));
}
