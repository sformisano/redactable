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
