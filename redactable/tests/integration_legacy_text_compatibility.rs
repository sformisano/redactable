//! Compatibility coverage for the deprecated author-composed text wrapper.

#[allow(deprecated)]
mod legacy_text {
    use redactable::{BypassTextRedaction, ToRedacted};

    #[test]
    fn preserves_constructor_clone_equality_and_escaped_debug() {
        let value = BypassTextRedaction("a\nb".to_owned());
        let clone = value.clone();

        assert_eq!(value, clone);
        assert_eq!(value.0, "a\nb");
        assert_eq!(format!("{value:?}"), r#"BypassTextRedaction("a\nb")"#);
    }

    #[test]
    fn preserves_text_and_json_fallback_for_empty_and_nonempty_values() {
        let value = BypassTextRedaction("approved".to_owned()).to_redacted();
        assert_eq!(value.text(), "approved");
        assert_eq!(value.json(), serde_json::json!({"message": "approved"}));

        let empty = BypassTextRedaction(String::new()).to_redacted();
        assert_eq!(empty.text(), "");
        assert_eq!(empty.json(), serde_json::json!({"message": ""}));
    }

    #[cfg(feature = "slog")]
    #[test]
    fn keeps_the_generic_slog_adapter_available() {
        use redactable::slog::SlogRedactedExt;

        let value = BypassTextRedaction("approved".to_owned());
        let _wrapped = value.slog_redacted();
        assert_eq!(
            value.slog_redacted_json().json(),
            serde_json::json!({"message": "approved"})
        );
    }

    #[cfg(feature = "tracing")]
    #[test]
    fn keeps_the_generic_tracing_adapter_available() {
        use redactable::tracing::TracingRedactedExt;

        let value = BypassTextRedaction("approved".to_owned());
        assert_eq!(format!("{}", value.tracing_redacted()), "approved");
    }
}
