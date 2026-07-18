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

        let creds = AuthCredentials("hunter2".into(), "sk_live_abc123def".into(), "alice".into());
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
        struct Credentials {
            #[sensitive(Secret)]
            password: String,
            username: String,
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
