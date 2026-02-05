//! Edge-case coverage for `TextRedactionPolicy` string handling.
//!
//! These tests focus on behavior across Unicode scalar values (including
//! multi-byte characters and combining marks) and on boundary cases such as
//! empty or very short inputs where keep policies may leave values unchanged.

use redactable::TextRedactionPolicy;

mod empty_and_short_strings {
    use super::*;

    #[test]
    fn uses_placeholder_for_empty_string() {
        let policy = TextRedactionPolicy::keep_last(4);
        assert_eq!(policy.apply_to(""), "[REDACTED]");

        let policy = TextRedactionPolicy::mask_first(2);
        assert_eq!(policy.apply_to(""), "[REDACTED]");

        let policy = TextRedactionPolicy::default_full();
        assert_eq!(policy.apply_to(""), "[REDACTED]");
    }

    #[test]
    fn handles_single_character() {
        let policy = TextRedactionPolicy::keep_last(4);
        assert_eq!(policy.apply_to("x"), "x");

        let policy = TextRedactionPolicy::mask_first(1);
        assert_eq!(policy.apply_to("x"), "*");
    }

    #[test]
    fn handles_exact_policy_length() {
        let text = "abcd";

        let policy = TextRedactionPolicy::keep_first(2);
        assert_eq!(policy.apply_to(text), "ab**");

        let policy = TextRedactionPolicy::keep_last(2);
        assert_eq!(policy.apply_to(text), "**cd");

        let policy = TextRedactionPolicy::mask_first(2);
        assert_eq!(policy.apply_to(text), "**cd");

        let policy = TextRedactionPolicy::mask_last(2);
        assert_eq!(policy.apply_to(text), "ab**");
    }
}

mod unicode {
    use super::*;

    #[test]
    fn handles_emoji() {
        let emoji_string = "secret🔒data";

        let policy = TextRedactionPolicy::keep_first(6);
        let result = policy.apply_to(emoji_string);
        assert_eq!(result, "secret*****");

        let policy = TextRedactionPolicy::keep_last(4);
        let result = policy.apply_to(emoji_string);
        assert_eq!(result, "*******data");
    }

    #[test]
    fn handles_multibyte_characters() {
        let chinese = "秘密数据";

        let policy = TextRedactionPolicy::keep_first(2);
        let result = policy.apply_to(chinese);
        assert_eq!(result, "秘密**");

        let policy = TextRedactionPolicy::mask_last(1);
        let result = policy.apply_to(chinese);
        assert_eq!(result, "秘密数*");
    }

    #[test]
    fn handles_combining_characters() {
        let combining = "cafe\u{0301}";

        let policy = TextRedactionPolicy::keep_first(4);
        let result = policy.apply_to(combining);
        assert_eq!(result, "cafe*");
    }

    #[test]
    fn handles_rtl_text() {
        let arabic = "سرية";

        let policy = TextRedactionPolicy::keep_first(2);
        let result = policy.apply_to(arabic);
        assert_eq!(result, "سر**");
    }

    #[test]
    fn handles_zero_width_characters() {
        let zwj_string = "test\u{200D}data";

        let policy = TextRedactionPolicy::keep_first(4);
        let result = policy.apply_to(zwj_string);
        assert_eq!(result, "test*****");
    }
}

mod special_cases {
    use super::*;

    #[test]
    fn handles_very_long_strings() {
        let long_string = "x".repeat(100_000);

        let policy = TextRedactionPolicy::keep_last(10);
        let result = policy.apply_to(&long_string);

        assert_eq!(result.len(), 100_000);
        assert!(result.starts_with(&"*".repeat(99_990)));
        assert!(result.ends_with("xxxxxxxxxx"));
    }

    #[test]
    fn handles_repeated_characters() {
        let repeated = "aaaaaaaaaa";

        let policy = TextRedactionPolicy::mask_first(5);
        let result = policy.apply_to(repeated);

        assert_eq!(result, "*****aaaaa");
    }

    #[test]
    fn handles_whitespace_only() {
        let spaces = "     ";

        let policy = TextRedactionPolicy::keep_first(2);
        let result = policy.apply_to(spaces);

        assert_eq!(result, "  ***");
    }

    #[test]
    fn handles_special_characters() {
        let special = "!@#$%^&*()";

        let policy = TextRedactionPolicy::keep_last(3);
        let result = policy.apply_to(special);

        assert_eq!(result, "********()");
    }

    #[test]
    fn handles_null_bytes() {
        let with_null = "test\0data";

        let policy = TextRedactionPolicy::mask_last(4);
        let result = policy.apply_to(with_null);

        assert_eq!(result, "test\0****");
    }
}

mod consistency {
    use super::*;

    #[test]
    fn produces_idempotent_results() {
        let text = "sensitive_data_12345";

        let policy = TextRedactionPolicy::keep_last(5);
        let once = policy.apply_to(text);
        let once_again = policy.apply_to(text);

        assert_eq!(once, once_again);
        assert_eq!(once, "***************12345");
    }
}
