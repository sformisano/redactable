//! Checked message arguments for the logging macros.

#[doc(hidden)]
#[macro_export]
macro_rules! __redactable_message {
    ($fmt:literal $(,)?) => {
        ::core::format_args!(::core::concat!($fmt))
    };
    ($fmt:literal, $($args:tt)+) => {
        $crate::__redactable_message!(@args $fmt [] $($args)+ ,)
    };
    (@args $fmt:literal [$($checked:tt)*] $(,)?) => {
        // concat! prevents implicit capture of unchecked variables in the caller.
        ::core::format_args!(::core::concat!($fmt), $($checked)*)
    };
    (@args $fmt:literal [$($checked:tt)*] $name:ident = $value:expr, $($rest:tt)*) => {
        $crate::__redactable_message!(@args $fmt [
            $($checked)* $name = $crate::__redactable_message!(@text $value),
        ] $($rest)*)
    };
    (@args $fmt:literal [$($checked:tt)*] $value:expr, $($rest:tt)*) => {
        $crate::__redactable_message!(@args $fmt [
            $($checked)* $crate::__redactable_message!(@text $value),
        ] $($rest)*)
    };
    (@text $value:expr) => {
        $crate::logging::__text($crate::__redactable_field!(json $value))
    };
}

#[cfg(test)]
mod tests {
    use crate::{BypassDisplayRedaction, Secret, SensitiveValue, ToRedacted};

    #[test]
    fn formats_only_the_declared_text_with_display_and_debug() {
        let user = SensitiveValue::<_, Secret>::from(String::from("private credential"));
        let saved = BypassDisplayRedaction("ready").to_redacted();
        assert_eq!(
            crate::__redactable_message!("literal {{braces}}").as_str(),
            Some("literal {braces}")
        );
        assert_eq!(
            crate::__redactable_message!("{{{name:>5.2}}} {0:?} / {0}", user, name = &saved,)
                .to_string(),
            "{   re} \"[REDACTED]\" / [REDACTED]"
        );
    }
}
