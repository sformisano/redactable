use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
#[error("value {value:x}")]
struct UnsupportedLowerHex {
    value: u32,
}

#[derive(SensitiveDisplay)]
#[error("value {value:x?}")]
struct UnsupportedLowerHexDebug {
    value: u32,
}

#[derive(SensitiveDisplay)]
#[error("value {value:X?}")]
struct UnsupportedUpperHexDebug {
    value: u32,
}

fn main() {}
