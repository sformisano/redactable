//! End-to-end tests for the public redaction API.
//!
//! These tests exercise the integration of:
//! - `Sensitive` derive traversal,
//! - policy-bound redaction selection, and
//! - container traversal for common standard library types.

#![allow(clippy::redundant_locals)]

use std::collections::{BTreeMap, HashMap};

use redactable::{
    NotSensitive, NotSensitiveDebugExt, NotSensitiveDisplayExt, NotSensitiveExt, Redactable,
    RedactableLeaf, RedactableWithPolicy, RedactedOutput, RedactedOutputExt, RedactionPolicy,
    Secret, Sensitive, SensitiveDisplay, SensitiveValue, TextRedactionPolicy, ToRedactedOutput,
    Token,
};

fn log_redacted<T: ToRedactedOutput>(value: &T) -> RedactedOutput {
    value.to_redacted_output()
}

mod text_policy {
    use super::*;

    #[test]
    fn applies_full_redaction_by_default() {
        let sensitive = String::from("my_secret_password");
        let policy = TextRedactionPolicy::default_full();
        let redacted = policy.apply_to(&sensitive);
        assert_eq!(redacted, "[REDACTED]");
    }
}

mod sensitive_derive {
    use super::*;

    mod structs {
        use super::*;

        #[test]
        fn redacts_classified_fields() {
            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(serde::Serialize))]
            struct Token {
                #[sensitive(Secret)]
                value: String,
            }

            let token = Token {
                value: "secret123".to_string(),
            };
            let redacted = token.redact();
            assert_eq!(redacted.value, "[REDACTED]");
        }

        #[test]
        fn redacts_nested_maps() {
            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(serde::Serialize))]
            struct ApiKeyEntry {
                #[sensitive(Token)]
                key: String,
            }

            let mut map: HashMap<String, ApiKeyEntry> = HashMap::new();
            map.insert(
                "primary".to_string(),
                ApiKeyEntry {
                    key: "sk_live_abc123".to_string(),
                },
            );
            let redacted = map.redact();
            // Token keeps last 4
            assert_eq!(redacted.get("primary").unwrap().key, "**********c123");
        }

        #[test]
        fn leaves_non_sensitive_fields_unchanged() {
            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(serde::Serialize))]
            struct User {
                #[sensitive(Secret)]
                password: String,
                username: String,
            }

            let user = User {
                password: "my_secret_password".into(),
                username: "john_doe".into(),
            };

            let redacted: User = user.redact();

            assert_eq!(redacted.password, "[REDACTED]");
            assert_eq!(redacted.username, "john_doe");
        }

        #[test]
        fn walks_nested_structs_automatically() {
            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(serde::Serialize))]
            struct Address {
                #[sensitive(Secret)]
                street: String,
                city: String,
            }

            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(serde::Serialize))]
            struct Person {
                #[sensitive(Secret)]
                name: String,
                address: Address,
            }

            let person = Person {
                name: "John Doe".into(),
                address: Address {
                    street: "123 Main Street".into(),
                    city: "Springfield".into(),
                },
            };

            let redacted = person.redact();

            assert_eq!(redacted.name, "[REDACTED]");
            assert_eq!(redacted.address.street, "[REDACTED]");
            assert_eq!(redacted.address.city, "Springfield");
        }

        #[test]
        fn handles_unit_structs() {
            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(serde::Serialize))]
            struct UnitMarker;

            let marker = UnitMarker;
            let redacted = marker.redact();
            let _ = redacted;
        }
    }

    mod tuple_structs {
        use super::*;

        #[test]
        fn redacts_annotated_fields() {
            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(serde::Serialize))]
            struct TupleSensitive(#[sensitive(Secret)] String, String);

            let tuple = TupleSensitive("secret_value".into(), "public_value".into());
            let redacted = tuple.redact();

            assert_eq!(redacted.0, "[REDACTED]");
            assert_eq!(redacted.1, "public_value");
        }

        #[test]
        fn applies_different_policies_to_different_fields() {
            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(serde::Serialize))]
            struct AuthCredentials(
                #[sensitive(Secret)] String,
                #[sensitive(Token)] String,
                String,
            );

            let creds =
                AuthCredentials("hunter2".into(), "sk_live_abc123def".into(), "alice".into());
            let redacted = creds.redact();

            assert_eq!(redacted.0, "[REDACTED]");
            assert_eq!(redacted.1, "*************3def"); // Token keeps last 4
            assert_eq!(redacted.2, "alice");
        }
    }

    mod enums {
        use super::*;

        #[test]
        fn redacts_struct_variant_fields() {
            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(serde::Serialize))]
            enum Credential {
                ApiKey {
                    #[sensitive(Token)]
                    key: String,
                },
                Password {
                    #[sensitive(Secret)]
                    value: String,
                },
            }

            let api_key = Credential::ApiKey {
                key: "sk_live_abcdef123456".into(),
            };
            let redacted = api_key.redact();

            match &redacted {
                Credential::ApiKey { key } => {
                    assert_eq!(key, "****************3456");
                }
                _ => panic!("Wrong variant"),
            }

            let password = Credential::Password {
                value: "super_secret".into(),
            };
            let redacted = password.redact();
            match &redacted {
                Credential::Password { value } => {
                    assert_eq!(value, "[REDACTED]");
                }
                _ => panic!("Wrong variant"),
            }
        }

        #[test]
        fn redacts_tuple_variant_fields() {
            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(serde::Serialize))]
            enum Auth {
                ApiKey(#[sensitive(Token)] String),
                Basic(#[sensitive(Secret)] String, String),
                None,
            }

            let api_key = Auth::ApiKey("sk_live_abc123def456ghi".into());
            let redacted = api_key.redact();
            match redacted {
                Auth::ApiKey(key) => assert_eq!(key, "*******************6ghi"),
                _ => panic!("Wrong variant"),
            }

            let basic = Auth::Basic("super_secret_password".into(), "alice".into());
            let redacted = basic.redact();
            match redacted {
                Auth::Basic(password, username) => {
                    assert_eq!(password, "[REDACTED]");
                    assert_eq!(username, "alice");
                }
                _ => panic!("Wrong variant"),
            }

            let none = Auth::None;
            let redacted = none.redact();
            match redacted {
                Auth::None => {}
                _ => panic!("Wrong variant"),
            }
        }
    }

    mod nested_fields {
        use super::*;

        #[test]
        fn walks_nested_structs_without_annotation() {
            #[derive(Clone, Sensitive, PartialEq)]
            #[cfg_attr(feature = "slog", derive(serde::Serialize))]
            #[sensitive(skip_debug)]
            struct Credentials {
                #[sensitive(Secret)]
                password: String,
                username: String,
            }

            impl std::fmt::Debug for Credentials {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.debug_struct("Credentials")
                        .field("password", &self.password)
                        .field("username", &self.username)
                        .finish()
                }
            }

            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(serde::Serialize))]
            struct UserWithAnnotation {
                creds: Credentials,
            }

            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(serde::Serialize))]
            struct UserWithoutAnnotation {
                creds: Credentials,
            }

            let creds = Credentials {
                password: "secret123".into(),
                username: "alice".into(),
            };

            let user_annotated = UserWithAnnotation {
                creds: creds.clone(),
            };
            let redacted_annotated = user_annotated.redact();
            assert_eq!(redacted_annotated.creds.password, "[REDACTED]");
            assert_eq!(redacted_annotated.creds.username, "alice");

            let user_unannotated = UserWithoutAnnotation {
                creds: creds.clone(),
            };
            let redacted_unannotated = user_unannotated.redact();
            assert_eq!(redacted_unannotated.creds.password, "[REDACTED]");
            assert_eq!(redacted_unannotated.creds.username, "alice");
        }

        #[test]
        fn walks_nested_generics() {
            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(serde::Serialize))]
            struct Inner {
                #[sensitive(Secret)]
                secret: String,
                public: i32,
            }

            #[derive(Clone, Sensitive)]
            #[cfg_attr(feature = "slog", derive(serde::Serialize))]
            struct Outer {
                inner: Inner,
                label: String,
            }

            let outer = Outer {
                inner: Inner {
                    secret: "inner_secret".into(),
                    public: 42,
                },
                label: "test".into(),
            };

            let redacted = outer.redact();

            assert_eq!(redacted.inner.secret, "[REDACTED]");
            assert_eq!(redacted.inner.public, 42);
            assert_eq!(redacted.label, "test");
        }
    }
}

mod sensitive_display_derive {
    use super::*;

    #[test]
    fn debug_is_unredacted_in_tests() {
        #[derive(SensitiveDisplay)]
        enum LoginError {
            #[error("login failed for {user} {password}")]
            Invalid {
                user: String,
                #[sensitive(Secret)]
                password: String,
            },
        }

        let err = LoginError::Invalid {
            user: "alice".into(),
            password: "hunter2".into(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("hunter2"));
    }
}

mod custom_policy {
    use super::*;

    #[test]
    fn applies_user_defined_policy() {
        #[derive(Clone, Copy)]
        struct InternalId;

        impl RedactionPolicy for InternalId {
            fn policy() -> TextRedactionPolicy {
                TextRedactionPolicy::keep_last(2)
            }
        }

        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Record {
            #[sensitive(InternalId)]
            id: String,
            name: String,
        }

        let record = Record {
            id: "user_abc123".into(),
            name: "Test".into(),
        };

        let redacted = record.redact();
        assert_eq!(redacted.id, "*********23");
        assert_eq!(redacted.name, "Test");
    }
}

mod container_traversal {
    use super::*;

    #[test]
    fn traverses_btreemap_values() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct SensitiveValue2 {
            #[sensitive(Secret)]
            value: String,
        }

        let mut map: BTreeMap<String, SensitiveValue2> = BTreeMap::new();
        map.insert(
            "key".to_string(),
            SensitiveValue2 {
                value: "value".to_string(),
            },
        );
        let redacted = map.redact();
        assert_eq!(redacted.get("key").unwrap().value, "[REDACTED]");
    }

    #[test]
    fn traverses_box_contents() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct BoxedSensitive {
            #[sensitive(Secret)]
            value: String,
        }

        let boxed: Box<BoxedSensitive> = Box::new(BoxedSensitive {
            value: "secret_in_box".into(),
        });
        let redacted = boxed.redact();

        assert_eq!(redacted.value, "[REDACTED]");
    }

    #[test]
    fn traverses_nested_boxes() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct DeepSensitive {
            #[sensitive(Secret)]
            value: String,
        }

        let nested: Box<Box<DeepSensitive>> = Box::new(Box::new(DeepSensitive {
            value: "deeply_nested".into(),
        }));
        let redacted = nested.redact();

        assert_eq!(redacted.value, "[REDACTED]");
    }

    #[test]
    fn traverses_generic_containers() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct SensitiveWrapper {
            #[sensitive(Secret)]
            value: String,
        }

        let vec_data = vec![
            SensitiveWrapper {
                value: "secret1".into(),
            },
            SensitiveWrapper {
                value: "secret2".into(),
            },
        ];
        let redacted = vec_data.redact();
        assert_eq!(redacted[0].value, "[REDACTED]");
        assert_eq!(redacted[1].value, "[REDACTED]");

        let opt_data = Some(SensitiveWrapper {
            value: "secret".into(),
        });
        let redacted = opt_data.redact();
        assert_eq!(redacted.unwrap().value, "[REDACTED]");

        let mut map_data: HashMap<String, SensitiveWrapper> = HashMap::new();
        map_data.insert(
            "key".into(),
            SensitiveWrapper {
                value: "secret".into(),
            },
        );
        let redacted = map_data.redact();
        assert_eq!(redacted["key"].value, "[REDACTED]");
    }

    #[test]
    fn traverses_option_vec_nesting() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct SensitiveItem {
            #[sensitive(Secret)]
            value: String,
        }

        let data: Option<Vec<SensitiveItem>> = Some(vec![
            SensitiveItem {
                value: "first".into(),
            },
            SensitiveItem {
                value: "second".into(),
            },
        ]);

        let redacted = data.redact();

        let items = redacted.unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].value, "[REDACTED]");
        assert_eq!(items[1].value, "[REDACTED]");
    }
}

mod scalar_redaction {
    use super::*;

    #[test]
    fn redacts_numeric_types_to_zero() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct ScalarData {
            #[sensitive(Secret)]
            secret_number: i32,
            #[sensitive(Secret)]
            secret_flag: bool,
            #[sensitive(Secret)]
            secret_char: char,
            public_number: i32,
        }

        let data = ScalarData {
            secret_number: 42,
            secret_flag: true,
            secret_char: '*',
            public_number: 100,
        };

        let redacted = data.redact();

        assert_eq!(redacted.secret_number, 0);
        assert!(!redacted.secret_flag);
        assert_eq!(redacted.secret_char, '*');
        assert_eq!(redacted.public_number, 100);
    }

    #[test]
    fn redacts_all_scalar_types() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct AllScalars {
            #[sensitive(Secret)]
            i8_val: i8,
            #[sensitive(Secret)]
            i16_val: i16,
            #[sensitive(Secret)]
            i32_val: i32,
            #[sensitive(Secret)]
            i64_val: i64,
            #[sensitive(Secret)]
            u8_val: u8,
            #[sensitive(Secret)]
            u16_val: u16,
            #[sensitive(Secret)]
            u32_val: u32,
            #[sensitive(Secret)]
            u64_val: u64,
            #[sensitive(Secret)]
            f32_val: f32,
            #[sensitive(Secret)]
            f64_val: f64,
            #[sensitive(Secret)]
            bool_val: bool,
            #[sensitive(Secret)]
            char_val: char,
        }

        let data = AllScalars {
            i8_val: 1,
            i16_val: 2,
            i32_val: 3,
            i64_val: 4,
            u8_val: 5,
            u16_val: 6,
            u32_val: 7,
            u64_val: 8,
            f32_val: 9.5,
            f64_val: 10.5,
            bool_val: true,
            char_val: 'A',
        };

        let redacted = data.redact();

        assert_eq!(redacted.i8_val, 0);
        assert_eq!(redacted.i16_val, 0);
        assert_eq!(redacted.i32_val, 0);
        assert_eq!(redacted.i64_val, 0);
        assert_eq!(redacted.u8_val, 0);
        assert_eq!(redacted.u16_val, 0);
        assert_eq!(redacted.u32_val, 0);
        assert_eq!(redacted.u64_val, 0);
        assert_eq!(redacted.f32_val, 0.0);
        assert_eq!(redacted.f64_val, 0.0);
        assert!(!redacted.bool_val);
        assert_eq!(redacted.char_val, '*');
    }
}

mod mixed_fields {
    use super::*;

    #[test]
    fn applies_correct_policy_to_each_field() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct MixedRecord {
            id: u64,
            #[sensitive(Secret)]
            ssn: String,
            name: String,
            #[sensitive(Secret)]
            internal_score: i32,
            #[sensitive(Token)]
            api_key: String,
            public_data: String,
        }

        let record = MixedRecord {
            id: 12345,
            ssn: "123-45-6789".into(),
            name: "John Doe".into(),
            internal_score: 95,
            api_key: "sk_test_abc123456789".into(),
            public_data: "visible".into(),
        };

        let redacted = record.redact();

        assert_eq!(redacted.id, 12345);
        assert_eq!(redacted.ssn, "[REDACTED]");
        assert_eq!(redacted.name, "John Doe");
        assert_eq!(redacted.internal_score, 0);
        assert_eq!(redacted.api_key, "****************6789");
        assert_eq!(redacted.public_data, "visible");
    }
}

mod policy_applicable {
    use super::*;

    #[test]
    fn applies_policy_to_option_vec() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct NestedWrappers {
            #[sensitive(Secret)]
            addresses: Option<Vec<String>>,
        }

        let n = NestedWrappers {
            addresses: Some(vec!["123 Main St".into(), "456 Oak Ave".into()]),
        };
        let redacted = n.redact();

        let addrs = redacted.addresses.unwrap();
        assert_eq!(addrs[0], "[REDACTED]");
        assert_eq!(addrs[1], "[REDACTED]");
    }

    #[test]
    fn applies_policy_to_vec_option() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct NestedWrappers {
            #[sensitive(Secret)]
            values: Vec<Option<String>>,
        }

        let n = NestedWrappers {
            values: vec![Some("secret1".into()), None, Some("secret2".into())],
        };
        let redacted = n.redact();

        assert_eq!(redacted.values[0], Some("[REDACTED]".into()));
        assert_eq!(redacted.values[1], None);
        assert_eq!(redacted.values[2], Some("[REDACTED]".into()));
    }

    #[test]
    fn applies_policy_to_deeply_nested_containers() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct DeepNest {
            #[sensitive(Secret)]
            values: Option<Vec<Option<String>>>,
        }

        let n = DeepNest {
            values: Some(vec![Some("secret".into()), None]),
        };
        let redacted = n.redact();

        let values = redacted.values.unwrap();
        assert_eq!(values[0], Some("[REDACTED]".into()));
        assert_eq!(values[1], None);
    }

    #[test]
    fn applies_policy_to_hashmap_vec() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct MapWithVec {
            #[sensitive(Secret)]
            data: HashMap<String, Vec<String>>,
        }

        let mut data = HashMap::new();
        data.insert("secrets".into(), vec!["secret1".into(), "secret2".into()]);

        let n = MapWithVec { data };
        let redacted = n.redact();

        assert_eq!(
            redacted.data.get("secrets"),
            Some(&vec!["[REDACTED]".to_string(), "[REDACTED]".to_string()])
        );
    }
}

mod external_types {
    use super::*;

    #[test]
    fn passes_through_unchanged_when_implementing_redactable_container() {
        #[derive(Clone, PartialEq, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct ExternalTimestamp(u64);

        #[derive(Clone, PartialEq, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct ExternalDecimal(f64);

        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Transaction {
            #[sensitive(Secret)]
            account_number: String,
            timestamp: ExternalTimestamp,
            amount: ExternalDecimal,
            description: String,
        }

        let tx = Transaction {
            account_number: "1234567890".into(),
            timestamp: ExternalTimestamp(1704067200),
            amount: ExternalDecimal(99.99),
            description: "Coffee".into(),
        };

        let redacted = tx.redact();

        assert_eq!(redacted.account_number, "[REDACTED]");
        assert_eq!(redacted.timestamp, ExternalTimestamp(1704067200));
        assert_eq!(redacted.amount, ExternalDecimal(99.99));
        assert_eq!(redacted.description, "Coffee");
    }

    #[test]
    fn redacts_via_sensitive_wrapper() {
        #[derive(Clone, Debug, PartialEq)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct ExternalId(String);

        impl RedactableLeaf for ExternalId {
            fn as_str(&self) -> &str {
                self.0.as_str()
            }

            fn from_redacted(redacted: String) -> Self {
                Self(redacted)
            }
        }

        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Record {
            #[sensitive(Secret)]
            token: String,
            external_id: SensitiveValue<ExternalId, Secret>,
        }

        let record = Record {
            token: "secret".to_string(),
            external_id: SensitiveValue::from(ExternalId("external".to_string())),
        };

        let redacted = record.redact();
        assert_eq!(redacted.token, "[REDACTED]");
        assert_eq!(
            redacted.external_id.expose(),
            &ExternalId("[REDACTED]".to_string())
        );
    }

    #[test]
    fn redacts_via_policy_trait() {
        #[derive(Clone, Debug, PartialEq)]
        #[cfg_attr(feature = "json", derive(serde::Serialize))]
        struct ExternalType(String);

        #[derive(Clone, Copy)]
        struct ExternalTypePolicy;

        impl RedactionPolicy for ExternalTypePolicy {
            fn policy() -> TextRedactionPolicy {
                TextRedactionPolicy::keep_last(2)
            }
        }

        impl RedactableWithPolicy<ExternalTypePolicy> for ExternalType {
            fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self {
                Self(policy.apply_to(&self.0))
            }

            fn redacted_string(&self, policy: &TextRedactionPolicy) -> String {
                policy.apply_to(&self.0)
            }
        }

        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "json", derive(serde::Serialize))]
        struct Record {
            id: SensitiveValue<ExternalType, ExternalTypePolicy>,
        }

        let record = Record {
            id: SensitiveValue::from(ExternalType("external".into())),
        };

        let redacted = record.clone().redact();
        assert_eq!(redacted.id.expose(), &ExternalType("******al".to_string()));
        assert_eq!(
            log_redacted(&record.id),
            RedactedOutput::Text("******al".to_string())
        );
    }

    #[test]
    fn chooses_trait_based_on_wrapper_usage() {
        #[derive(Clone, PartialEq, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        #[sensitive(skip_debug)]
        struct UserId {
            prefix: String,
            #[sensitive(Secret)]
            value: String,
        }

        impl std::fmt::Debug for UserId {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("UserId")
                    .field("prefix", &self.prefix)
                    .field("value", &self.value)
                    .finish()
            }
        }

        impl RedactableLeaf for UserId {
            fn as_str(&self) -> &str {
                &self.value
            }

            fn from_redacted(redacted: String) -> Self {
                Self {
                    prefix: "redacted".into(),
                    value: redacted,
                }
            }
        }

        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct AccountTraversed {
            user_id: UserId,
        }

        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct AccountAsLeaf {
            user_id: SensitiveValue<UserId, Token>,
        }

        let user_id = UserId {
            prefix: "usr".into(),
            value: "12345678".into(),
        };

        // Unannotated field uses Sensitive (traverses fields)
        let account_traversed = AccountTraversed {
            user_id: user_id.clone(),
        };
        let redacted_traversed = account_traversed.redact();
        assert_eq!(redacted_traversed.user_id.prefix, "usr");
        assert_eq!(redacted_traversed.user_id.value, "[REDACTED]");

        // SensitiveValue<T, Policy> wrapper uses RedactableLeaf (redacts as unit)
        let account_as_leaf = AccountAsLeaf {
            user_id: SensitiveValue::from(user_id.clone()),
        };
        let redacted_as_leaf = account_as_leaf.redact();
        assert_eq!(redacted_as_leaf.user_id.expose().prefix, "redacted");
        assert_eq!(redacted_as_leaf.user_id.expose().value, "****5678");
    }
}

mod not_sensitive_derive {
    use super::*;

    #[test]
    fn passes_through_all_fields_unchanged() {
        #[derive(Clone, Debug, NotSensitive)]
        struct PublicInfo {
            id: u64,
            label: String,
        }

        let value = PublicInfo {
            id: 42,
            label: "ok".to_string(),
        };

        let redacted = value.clone().redact();
        assert_eq!(redacted.id, value.id);
        assert_eq!(redacted.label, value.label);
    }

    #[test]
    fn does_not_walk_nested_sensitive_fields() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Inner {
            #[sensitive(Secret)]
            secret: String,
        }

        #[derive(Clone, Debug, NotSensitive)]
        struct Outer {
            inner: Inner,
        }

        let value = Outer {
            inner: Inner {
                secret: "top_secret".into(),
            },
        };

        let redacted = value.clone().redact();
        assert_eq!(redacted.inner.secret, value.inner.secret);
    }
}

mod not_sensitive_display_derive {
    use redactable::{NotSensitiveDisplay, RedactableDisplay};

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

        // RedactableDisplay delegates to Display
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

    // Test with skip_debug attribute
    #[derive(Clone, Debug, NotSensitiveDisplay)]
    #[not_sensitive_display(skip_debug)]
    struct WithOwnDebug {
        value: String,
    }

    impl std::fmt::Display for WithOwnDebug {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "WithOwnDebug({})", self.value)
        }
    }

    #[test]
    fn skip_debug_allows_own_debug_impl() {
        let value = WithOwnDebug {
            value: "test".into(),
        };

        // Display via RedactableDisplay
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
    // This works because NotSensitiveDisplay also generates RedactableContainer
    mod inside_sensitive_container {
        use redactable::{NotSensitiveDisplay, Redactable, RedactableDisplay, Secret, Sensitive};

        // A simple enum with NotSensitiveDisplay that has a Display impl
        #[derive(Clone, NotSensitiveDisplay, PartialEq)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        #[not_sensitive_display(skip_debug)]
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
            // This test proves NotSensitiveDisplay generates RedactableContainer
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
            #[not_sensitive_display(skip_debug)]
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
            // Verify RedactableDisplay still works correctly
            let decision = RetryDecision::Abort;
            let display = format!("{}", decision.redacted_display());
            assert_eq!(display, "Abort");
        }
    }
}

mod not_sensitive_attribute {
    use super::*;

    #[test]
    fn passes_through_foreign_types_in_struct() {
        #[derive(Clone, Debug, PartialEq)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct ForeignType {
            data: String,
        }

        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Container {
            #[not_sensitive]
            foreign: ForeignType,
            #[sensitive(Secret)]
            secret: String,
        }

        let value = Container {
            foreign: ForeignType {
                data: "external".into(),
            },
            secret: "hunter2".into(),
        };

        let redacted = value.clone().redact();

        assert_eq!(redacted.foreign, value.foreign);
        assert_eq!(redacted.secret, "[REDACTED]");
    }

    #[test]
    fn does_not_walk_nested_sensitive_fields() {
        #[derive(Clone, Sensitive, PartialEq)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct InnerSensitive {
            #[sensitive(Secret)]
            password: String,
        }

        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Outer {
            #[not_sensitive]
            inner: InnerSensitive,
            #[sensitive(Secret)]
            api_key: String,
        }

        let value = Outer {
            inner: InnerSensitive {
                password: "secret123".into(),
            },
            api_key: "sk_live_abc".into(),
        };

        let redacted = value.clone().redact();

        assert_eq!(redacted.inner.password, "secret123");
        assert_eq!(redacted.api_key, "[REDACTED]");
    }

    #[test]
    fn works_on_enum_variant_fields() {
        #[derive(Clone, Debug, PartialEq)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Metadata {
            version: u32,
        }

        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        enum Event {
            Success {
                #[not_sensitive]
                meta: Metadata,
                #[sensitive(Secret)]
                token: String,
            },
            Failure {
                #[not_sensitive]
                code: u32,
                message: String,
            },
        }

        let success = Event::Success {
            meta: Metadata { version: 1 },
            token: "secret_token".into(),
        };

        let failure = Event::Failure {
            code: 500,
            message: "error".into(),
        };

        let redacted_success = success.clone().redact();
        let redacted_failure = failure.clone().redact();

        match redacted_success {
            Event::Success { meta, token } => {
                assert_eq!(meta, Metadata { version: 1 });
                assert_eq!(token, "[REDACTED]");
            }
            _ => panic!("wrong variant"),
        }

        match redacted_failure {
            Event::Failure { code, message } => {
                assert_eq!(code, 500);
                assert_eq!(message, "error");
            }
            _ => panic!("wrong variant"),
        }
    }
}

mod not_sensitive_escape_hatches {
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
}

mod phantom_data {
    use std::marker::PhantomData;

    use super::*;

    /// External type that does NOT implement RedactableContainer.
    /// This simulates types like `chrono::DateTime<Utc>` or other third-party types.
    #[derive(Clone, Debug, PartialEq)]
    struct ExternalType;

    #[test]
    fn phantom_data_field_passes_through_without_bounds() {
        // This test verifies that PhantomData<T> fields work without
        // requiring T: RedactableContainer. If this compiles, the fix works.
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct TypedId<T> {
            id: String,
            #[sensitive(Secret)]
            secret: String,
            _marker: PhantomData<T>,
        }

        // ExternalType does NOT implement RedactableContainer.
        // If PhantomData wasn't handled specially, this would fail to compile.
        let typed_id: TypedId<ExternalType> = TypedId {
            id: "user_123".into(),
            secret: "hunter2".into(),
            _marker: PhantomData,
        };

        let redacted = typed_id.redact();

        // PhantomData passes through unchanged
        assert_eq!(redacted._marker, PhantomData);
        // Other fields work normally
        assert_eq!(redacted.id, "user_123");
        assert_eq!(redacted.secret, "[REDACTED]");
    }

    #[test]
    fn phantom_data_with_qualified_path() {
        // Test with fully qualified std::marker::PhantomData
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Wrapper<T> {
            value: String,
            _phantom: std::marker::PhantomData<T>,
        }

        let wrapper: Wrapper<ExternalType> = Wrapper {
            value: "test".into(),
            _phantom: std::marker::PhantomData,
        };

        let redacted = wrapper.redact();
        assert_eq!(redacted.value, "test");
    }

    #[test]
    fn multiple_phantom_data_fields() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct MultiPhantom<A, B, C> {
            #[sensitive(Secret)]
            data: String,
            _a: PhantomData<A>,
            _b: PhantomData<B>,
            _c: PhantomData<C>,
        }

        // None of A, B, C implement RedactableContainer
        let multi: MultiPhantom<ExternalType, ExternalType, ExternalType> = MultiPhantom {
            data: "secret".into(),
            _a: PhantomData,
            _b: PhantomData,
            _c: PhantomData,
        };

        let redacted = multi.redact();
        assert_eq!(redacted.data, "[REDACTED]");
    }

    #[test]
    fn phantom_data_in_enum_variant() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        enum TypedEvent<T> {
            Created {
                #[sensitive(Secret)]
                token: String,
                _marker: PhantomData<T>,
            },
            Deleted(PhantomData<T>),
        }

        let created: TypedEvent<ExternalType> = TypedEvent::Created {
            token: "secret_token".into(),
            _marker: PhantomData,
        };

        let redacted = created.redact();
        match redacted {
            TypedEvent::Created { token, _marker } => {
                assert_eq!(token, "[REDACTED]");
            }
            _ => panic!("wrong variant"),
        }

        let deleted: TypedEvent<ExternalType> = TypedEvent::Deleted(PhantomData);
        let redacted = deleted.redact();
        match redacted {
            TypedEvent::Deleted(_) => {}
            _ => panic!("wrong variant"),
        }
    }
}

mod to_redacted_output {
    use super::*;

    #[test]
    fn accepts_escape_hatches() {
        #[derive(Clone)]
        #[cfg_attr(feature = "json", derive(serde::Serialize))]
        struct ExternalId(String);

        impl RedactableLeaf for ExternalId {
            fn as_str(&self) -> &str {
                self.0.as_str()
            }

            fn from_redacted(redacted: String) -> Self {
                Self(redacted)
            }
        }

        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "json", derive(serde::Serialize))]
        struct Event {
            id: SensitiveValue<ExternalId, Secret>,
            status: String,
        }

        let event = Event {
            id: SensitiveValue::from(ExternalId("abc".into())),
            status: "ok".into(),
        };

        assert_eq!(
            log_redacted(&event.id),
            RedactedOutput::Text("[REDACTED]".to_string())
        );
        assert_eq!(
            log_redacted(&event.status.not_sensitive_display()),
            RedactedOutput::Text("ok".to_string())
        );

        let debug_output = log_redacted(&event.status.not_sensitive_debug());
        assert_eq!(debug_output, RedactedOutput::Text("\"ok\"".to_string()));

        let structured = log_redacted(&event.redacted_output());
        assert_eq!(
            structured,
            RedactedOutput::Text(
                "Event { id: SensitiveValue(\"[REDACTED]\"), status: \"ok\" }".to_string()
            )
        );
    }

    #[test]
    fn produces_debug_formatted_output() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Event {
            #[sensitive(Secret)]
            token: String,
            name: String,
        }

        let event = Event {
            token: "secret".into(),
            name: "alpha".into(),
        };

        let redacted_output = log_redacted(&event.redacted_output());
        assert_eq!(
            redacted_output,
            RedactedOutput::Text("Event { token: \"[REDACTED]\", name: \"alpha\" }".to_string())
        );
    }
}
