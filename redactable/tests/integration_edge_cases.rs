//! Edge-case coverage for `TextRedactionPolicy` string handling.
//!
//! These tests focus on behavior across Unicode scalar values (including
//! multi-byte characters and combining marks) and on boundary cases such as
//! empty or very short inputs where keep policies may leave values unchanged.

use redactable::TextRedactionPolicy;

#[test]
fn test_empty_string_uses_placeholder() {
    // Empty strings are fully redacted across policies.
    let policy = TextRedactionPolicy::keep_last(4);
    assert_eq!(policy.apply_to(""), "[REDACTED]");

    let policy = TextRedactionPolicy::mask_first(2);
    assert_eq!(policy.apply_to(""), "[REDACTED]");

    let policy = TextRedactionPolicy::default_full();
    assert_eq!(policy.apply_to(""), "[REDACTED]");
}

#[test]
fn test_single_character() {
    // keep_last leaves the value unchanged when it fully fits the keep span
    let policy = TextRedactionPolicy::keep_last(4);
    assert_eq!(policy.apply_to("x"), "x");

    let policy = TextRedactionPolicy::mask_first(1);
    assert_eq!(policy.apply_to("x"), "*");
}

#[test]
fn test_unicode_emoji() {
    let emoji_string = "secret🔒data";

    let policy = TextRedactionPolicy::keep_first(6);
    let result = policy.apply_to(emoji_string);
    assert_eq!(result, "secret*****");

    let policy = TextRedactionPolicy::keep_last(4);
    let result = policy.apply_to(emoji_string);
    assert_eq!(result, "*******data");
}

#[test]
fn test_unicode_multibyte() {
    // Chinese characters (3 bytes each in UTF-8)
    let chinese = "秘密数据";

    let policy = TextRedactionPolicy::keep_first(2);
    let result = policy.apply_to(chinese);
    // Should keep first 2 characters (6 bytes), mask remaining
    assert_eq!(result, "秘密**");

    let policy = TextRedactionPolicy::mask_last(1);
    let result = policy.apply_to(chinese);
    assert_eq!(result, "秘密数*");
}

#[test]
fn test_unicode_combining_characters() {
    // "é" as combining character (e + ◌́)
    let combining = "cafe\u{0301}";

    let policy = TextRedactionPolicy::keep_first(4);
    let result = policy.apply_to(combining);
    assert_eq!(result, "cafe*");
}

#[test]
fn test_rtl_text() {
    // Arabic text (right-to-left)
    let arabic = "سرية";

    let policy = TextRedactionPolicy::keep_first(2);
    let result = policy.apply_to(arabic);
    assert_eq!(result, "سر**");
}

#[test]
fn test_zero_width_characters() {
    // String with zero-width joiner
    let zwj_string = "test\u{200D}data";

    let policy = TextRedactionPolicy::keep_first(4);
    let result = policy.apply_to(zwj_string);
    assert_eq!(result, "test*****");
}

#[test]
fn test_very_long_string() {
    let long_string = "x".repeat(100_000);

    let policy = TextRedactionPolicy::keep_last(10);
    let result = policy.apply_to(&long_string);

    assert_eq!(result.len(), 100_000);
    assert!(result.starts_with(&"*".repeat(99_990)));
    assert!(result.ends_with("xxxxxxxxxx"));
}

#[test]
fn test_all_same_character() {
    let repeated = "aaaaaaaaaa";

    let policy = TextRedactionPolicy::mask_first(5);
    let result = policy.apply_to(repeated);

    assert_eq!(result, "*****aaaaa");
}

#[test]
fn test_whitespace_only() {
    let spaces = "     ";

    let policy = TextRedactionPolicy::keep_first(2);
    let result = policy.apply_to(spaces);

    assert_eq!(result, "  ***");
}

#[test]
fn test_special_characters() {
    let special = "!@#$%^&*()";

    let policy = TextRedactionPolicy::keep_last(3);
    let result = policy.apply_to(special);

    assert_eq!(result, "********()");
}

#[test]
fn test_null_byte_in_string() {
    let with_null = "test\0data";

    let policy = TextRedactionPolicy::mask_last(4);
    let result = policy.apply_to(with_null);

    // Should handle null bytes as regular characters
    assert_eq!(result, "test\0****");
}

#[test]
fn test_idempotent_redaction() {
    // Applying the same policy to the same string should always give the same result
    let text = "sensitive_data_12345";

    let policy = TextRedactionPolicy::keep_last(5);
    let once = policy.apply_to(text);
    let once_again = policy.apply_to(text);

    // Same input should always give same output
    assert_eq!(once, once_again);

    // The policy should produce expected result
    assert_eq!(once, "***************12345");
}

#[test]
fn test_policy_with_exact_length() {
    // String exactly matches prefix + suffix
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
