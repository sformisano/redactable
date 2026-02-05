//! Tests for wrapper types: `SensitiveValue<T, P>` and `NotSensitiveValue<T>`.
//!
//! These tests verify:
//! - Wrapper ergonomics (From, Deref, DerefMut, Debug)
//! - Redaction behavior within containers
//! - Orphan rule workarounds with `RedactableWithPolicy`

use redactable::{
    NotSensitiveValue, Redactable, RedactableLeaf, RedactableWithPolicy, RedactedOutput,
    RedactionPolicy, Secret, Sensitive, SensitiveValue, TextRedactionPolicy, ToRedactedOutput,
    Token,
};
#[cfg(feature = "slog")]
use serde::Serialize;

mod sensitive_value {
    use super::*;

    mod construction {
        use super::*;

        #[test]
        fn creates_from_value() {
            let sensitive = SensitiveValue::<String, Secret>::from("password".to_string());
            assert_eq!(sensitive.expose(), "password");
        }
    }

    mod access {
        use super::*;

        #[test]
        fn exposes_inner_value() {
            let sensitive = SensitiveValue::<String, Token>::from("tok_abc123".to_string());
            assert_eq!(sensitive.expose().len(), 10);
            assert!(sensitive.expose().starts_with("tok_"));
        }

        #[test]
        fn exposes_mutable_inner_value() {
            let mut sensitive = SensitiveValue::<String, Secret>::from("password".to_string());
            sensitive.expose_mut().push_str("123");
            assert_eq!(sensitive.expose(), "password123");
        }
    }

    mod formatting {
        use super::*;

        #[test]
        fn shows_redacted_in_debug() {
            let sensitive = SensitiveValue::<String, Secret>::from("hunter2".to_string());
            let debug = format!("{:?}", sensitive);
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains("hunter2"));
        }

        #[test]
        fn returns_redacted_string() {
            let sensitive = SensitiveValue::<String, Token>::from("sk_live_abc123def".to_string());
            assert_eq!(sensitive.redacted(), "*************3def");
        }

        #[test]
        fn converts_to_redacted_output() {
            let sensitive = SensitiveValue::<String, Secret>::from("secret".to_string());
            assert_eq!(
                sensitive.to_redacted_output(),
                RedactedOutput::Text("[REDACTED]".to_string())
            );
        }
    }

    mod in_container {
        use super::*;

        #[test]
        fn redacts_when_container_is_redacted() {
            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(Serialize))]
            struct Config {
                api_key: SensitiveValue<String, Token>,
            }

            let config = Config {
                api_key: SensitiveValue::from("sk_live_abc123def".to_string()),
            };
            let redacted = config.redact();
            assert_eq!(redacted.api_key.expose(), "*************3def");
        }

        #[test]
        fn works_with_custom_leaf_type() {
            #[derive(Clone, PartialEq, Debug)]
            #[cfg_attr(feature = "slog", derive(Serialize))]
            struct UserId(String);

            impl RedactableLeaf for UserId {
                fn as_str(&self) -> &str {
                    &self.0
                }

                fn from_redacted(redacted: String) -> Self {
                    Self(redacted)
                }
            }

            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(Serialize))]
            struct Request {
                user_id: SensitiveValue<UserId, Secret>,
            }

            let request = Request {
                user_id: SensitiveValue::from(UserId("user_12345".to_string())),
            };
            let redacted = request.redact();
            assert_eq!(redacted.user_id.expose(), &UserId("[REDACTED]".to_string()));
        }

        #[test]
        fn works_in_option() {
            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(Serialize))]
            struct MaybeSensitive {
                sensitive: Option<SensitiveValue<String, Secret>>,
            }

            let with_sensitive = MaybeSensitive {
                sensitive: Some(SensitiveValue::from("hidden".to_string())),
            };
            let redacted = with_sensitive.redact();
            assert_eq!(redacted.sensitive.unwrap().expose(), "[REDACTED]");

            let without_sensitive = MaybeSensitive { sensitive: None };
            let redacted = without_sensitive.redact();
            assert!(redacted.sensitive.is_none());
        }

        #[test]
        fn works_in_vec() {
            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(Serialize))]
            struct Tokens {
                values: Vec<SensitiveValue<String, Token>>,
            }

            let tokens = Tokens {
                values: vec![
                    SensitiveValue::from("sk_live_abc123".to_string()),
                    SensitiveValue::from("sk_test_xyz789".to_string()),
                ],
            };
            let redacted = tokens.redact();

            assert_eq!(redacted.values[0].expose(), "**********c123");
            assert_eq!(redacted.values[1].expose(), "**********z789");
        }
    }
}

mod not_sensitive_value {
    use super::*;

    mod construction {
        use super::*;

        #[test]
        fn creates_from_value() {
            #[derive(Clone, PartialEq, Debug)]
            struct ForeignType {
                data: String,
            }

            let wrapped = NotSensitiveValue::from(ForeignType {
                data: "test".to_string(),
            });
            assert_eq!(wrapped.data, "test");
        }
    }

    mod access {
        use super::*;

        #[test]
        fn derefs_to_inner() {
            #[derive(Clone)]
            struct ForeignType {
                value: i32,
            }

            let wrapped = NotSensitiveValue::from(ForeignType { value: 42 });
            assert_eq!(wrapped.value, 42);
        }

        #[test]
        fn derefs_mutably_to_inner() {
            #[derive(Clone)]
            struct ForeignType {
                value: i32,
            }

            let mut wrapped = NotSensitiveValue::from(ForeignType { value: 42 });
            wrapped.value = 100;
            assert_eq!(wrapped.value, 100);
        }
    }

    mod formatting {
        use super::*;

        #[test]
        fn shows_inner_in_debug() {
            #[allow(dead_code)]
            #[derive(Clone, Debug)]
            struct ForeignType {
                data: String,
            }

            let wrapped = NotSensitiveValue::from(ForeignType {
                data: "visible".to_string(),
            });
            let debug = format!("{:?}", wrapped);
            assert!(debug.contains("visible"));
            assert!(debug.contains("NotSensitiveValue"));
        }
    }

    mod in_container {
        use super::*;

        #[test]
        fn passes_through_unchanged() {
            #[derive(Clone, Debug, PartialEq)]
            #[cfg_attr(feature = "slog", derive(Serialize))]
            struct ForeignConfig {
                timeout: u64,
                retries: u32,
            }

            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(Serialize))]
            struct AppConfig {
                #[sensitive(Secret)]
                api_key: String,
                foreign: NotSensitiveValue<ForeignConfig>,
            }

            let config = AppConfig {
                api_key: "secret_key".to_string(),
                foreign: NotSensitiveValue::from(ForeignConfig {
                    timeout: 30,
                    retries: 3,
                }),
            };
            let redacted = config.redact();

            assert_eq!(redacted.api_key, "[REDACTED]");
            assert_eq!(redacted.foreign.timeout, 30);
            assert_eq!(redacted.foreign.retries, 3);
        }

        #[test]
        fn does_not_walk_nested_sensitive_fields() {
            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(Serialize))]
            struct InnerSensitive {
                #[sensitive(Secret)]
                password: String,
            }

            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(Serialize))]
            struct Outer {
                inner: NotSensitiveValue<InnerSensitive>,
            }

            let outer = Outer {
                inner: NotSensitiveValue::from(InnerSensitive {
                    password: "hunter2".to_string(),
                }),
            };
            let redacted = outer.redact();

            // Password is NOT redacted because NotSensitiveValue is a passthrough
            assert_eq!(redacted.inner.password, "hunter2");
        }
    }
}

mod orphan_rule_workaround {
    use super::*;

    // Simulate a foreign type from another crate
    #[derive(Clone, PartialEq, Debug)]
    #[cfg_attr(feature = "slog", derive(Serialize))]
    struct ForeignId(String);

    #[derive(Clone, Copy)]
    struct ForeignIdPolicy;

    impl RedactionPolicy for ForeignIdPolicy {
        fn policy() -> TextRedactionPolicy {
            TextRedactionPolicy::keep_last(4)
        }
    }

    impl RedactableWithPolicy<ForeignIdPolicy> for ForeignId {
        fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self {
            Self(policy.apply_to(&self.0))
        }

        fn redacted_string(&self, policy: &TextRedactionPolicy) -> String {
            policy.apply_to(&self.0)
        }
    }

    #[test]
    fn redacts_foreign_type_via_sensitive_wrapper() {
        let wrapped = SensitiveValue::<ForeignId, ForeignIdPolicy>::from(ForeignId(
            "external_12345".to_string(),
        ));
        assert_eq!(wrapped.redacted(), "**********2345");
    }

    #[test]
    fn redacts_foreign_type_in_container() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(Serialize))]
        struct Integration {
            external_id: SensitiveValue<ForeignId, ForeignIdPolicy>,
            #[sensitive(Secret)]
            api_key: String,
        }

        let integration = Integration {
            external_id: SensitiveValue::from(ForeignId("ext_abcdefgh".to_string())),
            api_key: "secret_key".to_string(),
        };
        let redacted = integration.redact();

        assert_eq!(
            redacted.external_id.expose(),
            &ForeignId("********efgh".to_string())
        );
        assert_eq!(redacted.api_key, "[REDACTED]");
    }

    #[test]
    fn converts_to_redacted_output() {
        let wrapped =
            SensitiveValue::<ForeignId, ForeignIdPolicy>::from(ForeignId("id_xyz123".to_string()));
        assert_eq!(
            wrapped.to_redacted_output(),
            RedactedOutput::Text("*****z123".to_string())
        );
    }

    #[test]
    fn reuses_builtin_policy_logic() {
        struct MyTokenPolicy;
        impl RedactionPolicy for MyTokenPolicy {
            fn policy() -> TextRedactionPolicy {
                Token::policy()
            }
        }

        #[derive(Clone, PartialEq, Debug)]
        struct ExternalToken(String);

        impl RedactableWithPolicy<MyTokenPolicy> for ExternalToken {
            fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self {
                Self(policy.apply_to(&self.0))
            }

            fn redacted_string(&self, policy: &TextRedactionPolicy) -> String {
                policy.apply_to(&self.0)
            }
        }

        let wrapped = SensitiveValue::<ExternalToken, MyTokenPolicy>::from(ExternalToken(
            "tok_live_secret".to_string(),
        ));
        assert_eq!(wrapped.redacted(), "***********cret");
    }
}

mod combined_wrappers {
    use super::*;

    #[test]
    fn mixes_different_wrapper_types_in_same_container() {
        #[derive(Clone, Debug)]
        #[cfg_attr(feature = "slog", derive(Serialize))]
        struct ForeignMetadata {
            version: String,
        }

        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(Serialize))]
        struct Service {
            #[sensitive(Secret)]
            credentials: String,
            api_token: SensitiveValue<String, Token>,
            metadata: NotSensitiveValue<ForeignMetadata>,
        }

        let service = Service {
            credentials: "password123".to_string(),
            api_token: SensitiveValue::from("sk_live_abc123def".to_string()),
            metadata: NotSensitiveValue::from(ForeignMetadata {
                version: "1.0.0".to_string(),
            }),
        };
        let redacted = service.redact();

        assert_eq!(redacted.credentials, "[REDACTED]");
        assert_eq!(redacted.api_token.expose(), "*************3def");
        assert_eq!(redacted.metadata.version, "1.0.0");
    }

    #[test]
    fn not_sensitive_derive_and_wrapper_coexist() {
        use redactable::NotSensitive;

        #[derive(Clone, Debug, NotSensitive)]
        #[cfg_attr(feature = "slog", derive(Serialize))]
        struct PublicData {
            name: String,
        }

        #[derive(Clone, Debug)]
        #[cfg_attr(feature = "slog", derive(Serialize))]
        struct ForeignData {
            value: i32,
        }

        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(Serialize))]
        struct Combined {
            public: PublicData,
            foreign: NotSensitiveValue<ForeignData>,
            #[sensitive(Secret)]
            password: String,
        }

        let combined = Combined {
            public: PublicData {
                name: "Alice".to_string(),
            },
            foreign: NotSensitiveValue::from(ForeignData { value: 42 }),
            password: "password".to_string(),
        };
        let redacted = combined.redact();

        assert_eq!(redacted.public.name, "Alice");
        assert_eq!(redacted.foreign.value, 42);
        assert_eq!(redacted.password, "[REDACTED]");
    }
}
