//! Text redaction strategies for string-like values.
//!
//! This module provides [`TextRedactionPolicy`] and its configuration types
//! for transforming sensitive strings. Policies are pure string transformations
//! that do not traverse structures or make runtime decisions about sensitivity.

use std::borrow::Cow;

/// Default placeholder used for full redaction.
pub const REDACTED_PLACEHOLDER: &str = "[REDACTED]";

/// Default character used to mask sensitive characters.
pub const MASK_CHAR: char = '*';

/// Configuration that keeps selected segments visible while masking the remainder.
///
/// The policy operates on Unicode scalar values. If the configuration keeps the
/// entire value visible, the output is unchanged.
///
/// Use the constructor methods [`KeepConfig::first`] and [`KeepConfig::last`]
/// to create instances.
#[derive(Clone, Copy, Debug)]
pub struct KeepConfig {
    /// Number of leading characters to keep visible.
    visible_prefix: usize,
    /// Number of trailing characters to keep visible.
    visible_suffix: usize,
    /// Symbol used to mask the middle.
    mask_char: char,
}

impl KeepConfig {
    /// Constructs a configuration that keeps only the first `visible_prefix` scalar values.
    #[must_use]
    pub fn first(visible_prefix: usize) -> Self {
        Self {
            visible_prefix,
            visible_suffix: 0,
            mask_char: MASK_CHAR,
        }
    }

    /// Constructs a configuration that keeps only the last `visible_suffix` scalar values.
    #[must_use]
    pub fn last(visible_suffix: usize) -> Self {
        Self {
            visible_prefix: 0,
            visible_suffix,
            mask_char: MASK_CHAR,
        }
    }

    /// Constructs a configuration that keeps both leading and trailing characters visible.
    ///
    /// If `visible_prefix + visible_suffix >= total_length`, the entire value
    /// is kept visible (no masking occurs).
    #[must_use]
    pub fn both(visible_prefix: usize, visible_suffix: usize) -> Self {
        Self {
            visible_prefix,
            visible_suffix,
            mask_char: MASK_CHAR,
        }
    }

    /// Uses a specific masking character.
    #[must_use]
    pub fn with_mask_char(mut self, mask_char: char) -> Self {
        self.mask_char = mask_char;
        self
    }

    /// Sets the masking character in place.
    pub(crate) fn set_mask_char(&mut self, mask_char: char) {
        self.mask_char = mask_char;
    }

    /// Applies the policy to a string value.
    ///
    /// Empty strings are fully redacted using [`REDACTED_PLACEHOLDER`].
    ///
    /// If `visible_prefix + visible_suffix >= total_length`, the entire value
    /// is kept visible (no masking occurs).
    pub(crate) fn apply_to(&self, value: &str) -> String {
        let mut chars: Vec<char> = value.chars().collect();
        let total = chars.len();
        if total == 0 {
            return REDACTED_PLACEHOLDER.to_string();
        }

        // If keep spans cover or exceed the total length, return unchanged
        if self.visible_prefix.saturating_add(self.visible_suffix) >= total {
            return chars.into_iter().collect();
        }

        // Mask the middle portion
        for ch in &mut chars[self.visible_prefix..(total - self.visible_suffix)] {
            *ch = self.mask_char;
        }
        chars.into_iter().collect()
    }
}

/// Configuration that masks selected segments while leaving the remainder unchanged.
///
/// Masking operates on Unicode scalar values and bounds the masked spans for
/// short inputs.
///
/// Use the constructor methods [`MaskConfig::first`] and [`MaskConfig::last`]
/// to create instances.
#[derive(Clone, Copy, Debug)]
#[allow(clippy::struct_field_names)] // Field names are descriptive for internal use
pub struct MaskConfig {
    /// Number of leading characters to mask.
    mask_prefix: usize,
    /// Number of trailing characters to mask.
    mask_suffix: usize,
    /// Symbol used to mask the selected segments.
    mask_char: char,
}

impl MaskConfig {
    /// Masks only the initial `mask_prefix` characters.
    #[must_use]
    pub fn first(mask_prefix: usize) -> Self {
        Self {
            mask_prefix,
            mask_suffix: 0,
            mask_char: MASK_CHAR,
        }
    }

    /// Masks only the final `mask_suffix` characters.
    #[must_use]
    pub fn last(mask_suffix: usize) -> Self {
        Self {
            mask_prefix: 0,
            mask_suffix,
            mask_char: MASK_CHAR,
        }
    }

    /// Masks both leading and trailing characters.
    ///
    /// If `mask_prefix + mask_suffix >= total_length`, the entire value
    /// is masked.
    #[must_use]
    pub fn both(mask_prefix: usize, mask_suffix: usize) -> Self {
        Self {
            mask_prefix,
            mask_suffix,
            mask_char: MASK_CHAR,
        }
    }

    /// Uses a specific masking character.
    #[must_use]
    pub fn with_mask_char(mut self, mask_char: char) -> Self {
        self.mask_char = mask_char;
        self
    }

    /// Sets the masking character in place.
    pub(crate) fn set_mask_char(&mut self, mask_char: char) {
        self.mask_char = mask_char;
    }

    /// Applies the policy to a string value.
    ///
    /// Empty strings are fully redacted using [`REDACTED_PLACEHOLDER`].
    ///
    /// If `mask_prefix + mask_suffix >= total_length`, the entire value
    /// is masked.
    pub(crate) fn apply_to(&self, value: &str) -> String {
        let mut chars: Vec<char> = value.chars().collect();
        let total = chars.len();
        if total == 0 {
            return REDACTED_PLACEHOLDER.to_string();
        }

        // If mask spans cover or exceed total length, mask everything
        if self.mask_prefix.saturating_add(self.mask_suffix) >= total {
            chars.fill(self.mask_char);
            return chars.into_iter().collect();
        }

        // Mask the prefix portion
        for ch in &mut chars[..self.mask_prefix] {
            *ch = self.mask_char;
        }

        // Mask the suffix portion
        if self.mask_suffix > 0 {
            let start = total - self.mask_suffix;
            for ch in &mut chars[start..] {
                *ch = self.mask_char;
            }
        }

        chars.into_iter().collect()
    }
}

/// Configuration for email address redaction.
///
/// Masks the local part (before `@`) while preserving the domain. If no `@` is
/// present, the input is masked like a prefix-keep policy.
#[derive(Clone, Copy, Debug)]
pub struct EmailConfig {
    /// Number of leading characters of the local part to keep visible.
    visible_prefix: usize,
    /// Symbol used to mask the local part.
    mask_char: char,
}

impl EmailConfig {
    /// Creates a new email config that keeps the first `visible_prefix` chars of the local part.
    #[must_use]
    pub fn new(visible_prefix: usize) -> Self {
        Self {
            visible_prefix,
            mask_char: MASK_CHAR,
        }
    }

    /// Uses a specific masking character.
    #[must_use]
    pub fn with_mask_char(mut self, mask_char: char) -> Self {
        self.mask_char = mask_char;
        self
    }

    /// Sets the masking character in place.
    pub(crate) fn set_mask_char(&mut self, mask_char: char) {
        self.mask_char = mask_char;
    }

    /// Applies the policy to an email address.
    ///
    /// If there's no `@`, the value is masked like a prefix-keep policy.
    pub(crate) fn apply_to(&self, value: &str) -> String {
        let chars: Vec<char> = value.chars().collect();
        let total = chars.len();
        if total == 0 {
            return REDACTED_PLACEHOLDER.to_string();
        }

        if let Some(at_pos) = value.find('@') {
            let local = &value[..at_pos];
            let domain = &value[at_pos..]; // includes the @

            let local_chars: Vec<char> = local.chars().collect();
            let local_len = local_chars.len();

            if self.visible_prefix >= local_len {
                // Keep entire local part
                return value.to_string();
            }

            let visible: String = local_chars[..self.visible_prefix].iter().collect();
            let masked_count = local_len - self.visible_prefix;
            let masked: String = std::iter::repeat_n(self.mask_char, masked_count).collect();

            format!("{visible}{masked}{domain}")
        } else {
            if self.visible_prefix >= total {
                return value.to_string();
            }

            let mut result = chars;
            for ch in &mut result[self.visible_prefix..] {
                *ch = self.mask_char;
            }
            result.into_iter().collect()
        }
    }
}

/// A redaction strategy for string-like values.
///
/// All strategies operate on Unicode scalar values and return an owned `String`.
// Use `Cow` so callers can provide borrowed or owned placeholders.
#[derive(Clone, Debug)]
pub enum TextRedactionPolicy {
    /// Replace the entire value with a fixed placeholder.
    Full {
        /// The placeholder text to use.
        placeholder: Cow<'static, str>,
    },
    /// Keep configured segments visible while masking everything else.
    Keep(KeepConfig),
    /// Mask configured segments while leaving the remainder untouched.
    Mask(MaskConfig),
    /// Email-specific: mask local part while preserving domain.
    Email(EmailConfig),
}

impl TextRedactionPolicy {
    /// Constructs [`TextRedactionPolicy::Full`] using [`REDACTED_PLACEHOLDER`].
    #[must_use]
    pub fn default_full() -> Self {
        Self::Full {
            placeholder: Cow::Borrowed(REDACTED_PLACEHOLDER),
        }
    }

    /// Constructs [`TextRedactionPolicy::Full`] using a custom placeholder.
    #[must_use]
    pub fn full_with<P>(placeholder: P) -> Self
    where
        P: Into<Cow<'static, str>>,
    {
        Self::Full {
            placeholder: placeholder.into(),
        }
    }

    /// Constructs [`TextRedactionPolicy::Keep`] from an explicit configuration.
    #[must_use]
    pub fn keep_with(config: KeepConfig) -> Self {
        Self::Keep(config)
    }

    /// Keeps only the first `visible_prefix` scalar values in clear text.
    #[must_use]
    pub fn keep_first(visible_prefix: usize) -> Self {
        Self::keep_with(KeepConfig::first(visible_prefix))
    }

    /// Keeps only the last `visible_suffix` scalar values in clear text.
    #[must_use]
    pub fn keep_last(visible_suffix: usize) -> Self {
        Self::keep_with(KeepConfig::last(visible_suffix))
    }

    /// Masks segments using the provided configuration.
    #[must_use]
    pub fn mask_with(config: MaskConfig) -> Self {
        Self::Mask(config)
    }

    /// Masks the first `mask_prefix` scalar values.
    #[must_use]
    pub fn mask_first(mask_prefix: usize) -> Self {
        Self::mask_with(MaskConfig::first(mask_prefix))
    }

    /// Masks the last `mask_suffix` scalar values.
    #[must_use]
    pub fn mask_last(mask_suffix: usize) -> Self {
        Self::mask_with(MaskConfig::last(mask_suffix))
    }

    /// Email-specific policy: keeps first `visible_prefix` chars of local part, preserves domain.
    ///
    /// # Example
    /// ```
    /// use redactable::TextRedactionPolicy;
    ///
    /// let policy = TextRedactionPolicy::email_local(2);
    /// assert_eq!(policy.apply_to("alice@example.com"), "al***@example.com");
    /// assert_eq!(policy.apply_to("bob@company.io"), "bo*@company.io");
    /// ```
    #[must_use]
    pub fn email_local(visible_prefix: usize) -> Self {
        Self::Email(EmailConfig::new(visible_prefix))
    }

    /// Overrides the masking character used by keep/mask/email policies.
    ///
    /// This method has no effect on [`TextRedactionPolicy::Full`] because full
    /// redaction replaces the entire value with a placeholder string rather
    /// than masking individual characters.
    #[must_use]
    pub fn with_mask_char(mut self, mask_char: char) -> Self {
        match &mut self {
            TextRedactionPolicy::Full { .. } => {}
            TextRedactionPolicy::Keep(config) => {
                config.set_mask_char(mask_char);
            }
            TextRedactionPolicy::Mask(config) => {
                config.set_mask_char(mask_char);
            }
            TextRedactionPolicy::Email(config) => {
                config.set_mask_char(mask_char);
            }
        }
        self
    }

    /// Applies the policy to `value`.
    ///
    /// This method is total (it does not return errors).
    #[must_use]
    pub fn apply_to(&self, value: &str) -> String {
        match self {
            TextRedactionPolicy::Full { placeholder } => placeholder.clone().into_owned(),
            TextRedactionPolicy::Keep(config) => config.apply_to(value),
            TextRedactionPolicy::Mask(config) => config.apply_to(value),
            TextRedactionPolicy::Email(config) => config.apply_to(value),
        }
    }
}

impl std::default::Default for TextRedactionPolicy {
    fn default() -> Self {
        Self::default_full()
    }
}

#[cfg(test)]
mod tests {
    use super::{KeepConfig, MaskConfig, REDACTED_PLACEHOLDER, TextRedactionPolicy};

    #[test]
    fn keep_policy_allows_full_visibility() {
        let policy = TextRedactionPolicy::keep_with(KeepConfig::first(3));
        assert_eq!(policy.apply_to("ab"), "ab");
    }

    #[test]
    fn keep_policy_respects_mask_char() {
        let policy = TextRedactionPolicy::keep_first(2).with_mask_char('#');
        assert_eq!(policy.apply_to("abcdef"), "ab####");
    }

    #[test]
    fn full_policy_uses_default_placeholder() {
        let policy = TextRedactionPolicy::default_full();
        assert_eq!(policy.apply_to("secret"), REDACTED_PLACEHOLDER);
    }

    #[test]
    fn full_policy_uses_custom_placeholder() {
        let policy = TextRedactionPolicy::full_with("<redacted>");
        assert_eq!(policy.apply_to("secret"), "<redacted>");
    }

    #[test]
    fn mask_policy_masks_first_and_last_segments() {
        let policy = TextRedactionPolicy::mask_first(2);
        assert_eq!(policy.apply_to("abcdef"), "**cdef");

        let policy = TextRedactionPolicy::mask_last(3);
        assert_eq!(policy.apply_to("abcdef"), "abc***");
    }

    #[test]
    fn mask_policy_respects_custom_mask_char() {
        let policy = TextRedactionPolicy::mask_with(MaskConfig::last(2)).with_mask_char('#');
        assert_eq!(policy.apply_to("abcd"), "ab##");
    }

    #[test]
    fn email_policy_preserves_domain() {
        let policy = TextRedactionPolicy::email_local(2);
        assert_eq!(policy.apply_to("alice@example.com"), "al***@example.com");
        assert_eq!(policy.apply_to("bob@company.io"), "bo*@company.io");
        assert_eq!(policy.apply_to("x@a.com"), "x@a.com"); // single char local, prefix=2 keeps all
    }

    #[test]
    fn email_policy_masks_non_email_inputs() {
        let policy = TextRedactionPolicy::email_local(2);

        // No @ symbol - mask like prefix keep
        assert_eq!(policy.apply_to("noatsymbol"), "no********");

        // Empty string
        assert_eq!(policy.apply_to(""), REDACTED_PLACEHOLDER);

        // Short local part
        assert_eq!(policy.apply_to("ab@x.com"), "ab@x.com"); // exactly 2 chars, no masking

        // Very short email
        assert_eq!(policy.apply_to("a@b.c"), "a@b.c"); // 1 char local, prefix=2 keeps all
    }

    #[test]
    fn email_policy_respects_mask_char() {
        let policy = TextRedactionPolicy::email_local(2).with_mask_char('#');
        assert_eq!(policy.apply_to("alice@example.com"), "al###@example.com");
    }

    #[test]
    fn empty_string_returns_placeholder_for_policies() {
        // Empty strings are fully redacted for keep/mask/email policies.
        let keep_policy = TextRedactionPolicy::keep_first(4);
        assert_eq!(keep_policy.apply_to(""), REDACTED_PLACEHOLDER);

        let mask_policy = TextRedactionPolicy::mask_first(4);
        assert_eq!(mask_policy.apply_to(""), REDACTED_PLACEHOLDER);

        let email_policy = TextRedactionPolicy::email_local(2);
        assert_eq!(email_policy.apply_to(""), REDACTED_PLACEHOLDER);

        let full_policy = TextRedactionPolicy::default_full();
        assert_eq!(full_policy.apply_to(""), REDACTED_PLACEHOLDER);
    }

    #[test]
    fn keep_both_overlap_keeps_entire_value() {
        // When prefix + suffix >= total, keep everything visible
        let policy = TextRedactionPolicy::keep_with(KeepConfig::both(2, 2));
        assert_eq!(policy.apply_to("abc"), "abc"); // 2 + 2 = 4 >= 3

        let policy = TextRedactionPolicy::keep_with(KeepConfig::both(3, 3));
        assert_eq!(policy.apply_to("abcd"), "abcd"); // 3 + 3 = 6 >= 4

        // Edge case: exactly equals total
        let policy = TextRedactionPolicy::keep_with(KeepConfig::both(2, 2));
        assert_eq!(policy.apply_to("abcd"), "abcd"); // 2 + 2 = 4 >= 4

        // Overflow-safe: large values still keep entire value
        let policy = TextRedactionPolicy::keep_with(KeepConfig::both(usize::MAX, usize::MAX));
        assert_eq!(policy.apply_to("abcd"), "abcd");
    }

    #[test]
    fn mask_both_overlap_masks_entire_value() {
        // When prefix + suffix >= total, mask everything
        let policy = TextRedactionPolicy::mask_with(MaskConfig::both(2, 2));
        assert_eq!(policy.apply_to("abc"), "***"); // 2 + 2 = 4 >= 3

        let policy = TextRedactionPolicy::mask_with(MaskConfig::both(3, 3));
        assert_eq!(policy.apply_to("abcd"), "****"); // 3 + 3 = 6 >= 4

        // Edge case: exactly equals total
        let policy = TextRedactionPolicy::mask_with(MaskConfig::both(2, 2));
        assert_eq!(policy.apply_to("abcd"), "****"); // 2 + 2 = 4 >= 4

        // Overflow-safe: large values still mask entire value
        let policy = TextRedactionPolicy::mask_with(MaskConfig::both(usize::MAX, usize::MAX));
        assert_eq!(policy.apply_to("abcd"), "****");
    }

    #[test]
    fn keep_both_no_overlap() {
        // Normal case: prefix + suffix < total
        let policy = TextRedactionPolicy::keep_with(KeepConfig::both(2, 2));
        assert_eq!(policy.apply_to("abcdef"), "ab**ef"); // keep first 2 and last 2
    }

    #[test]
    fn mask_both_no_overlap() {
        // Normal case: prefix + suffix < total
        let policy = TextRedactionPolicy::mask_with(MaskConfig::both(2, 2));
        assert_eq!(policy.apply_to("abcdef"), "**cd**"); // mask first 2 and last 2
    }
}
