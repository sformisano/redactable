use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct Display<T> {
    #[not_sensitive]
    value: T,
}

#[derive(SensitiveDisplay)]
#[error("{0:?}")]
struct Debug<T>(#[not_sensitive] T);

#[derive(SensitiveDisplay)]
#[error("{value:?} {value}")]
struct Both<T: std::fmt::Debug> {
    #[not_sensitive]
    value: T,
}

fn main() {}
