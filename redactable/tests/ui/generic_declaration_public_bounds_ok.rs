use redactable::{DeclaredFormatting, RedactableWithFormatter, SensitiveDisplay, SensitiveDual, ToRedacted};
use std::fmt;

#[derive(Clone, serde::Serialize)]
struct RefOnly;

impl fmt::Display for &RefOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("public")
    }
}

impl fmt::Debug for &RefOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("public debug")
    }
}

#[derive(Clone, serde::Serialize)]
struct DisplayOnly;
impl fmt::Display for DisplayOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("display")
    }
}
impl fmt::Debug for &DisplayOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("borrowed debug")
    }
}

#[derive(Clone, Debug, serde::Serialize)]
struct DebugOnly;
impl fmt::Display for &DebugOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("borrowed display")
    }
}

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct Display<T> where for<'a> &'a T: fmt::Display {
    #[not_sensitive]
    value: T,
}

#[derive(SensitiveDisplay)]
#[error("{0:?}")]
struct Debug<T>(#[not_sensitive] T) where for<'a> &'a T: fmt::Debug;

#[derive(SensitiveDisplay)]
enum Both<T> where for<'a> &'a T: fmt::Display + fmt::Debug {
    #[error("{value} {value:?}")]
    Named { #[not_sensitive] value: T },
    #[error("{0:?} {0}")]
    Tuple(#[not_sensitive] T),
}

#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
struct NamedDisplayFirst<T> where for<'a> &'a T: fmt::Display + fmt::Debug {
    #[not_sensitive]
    value: T,
}

#[derive(SensitiveDisplay)]
#[error("{value:?} {value}")]
struct NamedDebugFirst<T> where for<'a> &'a T: fmt::Display + fmt::Debug {
    #[not_sensitive]
    value: T,
}

#[derive(SensitiveDisplay)]
#[error("{0} {0:?}")]
struct TupleDisplayFirst<T>(#[not_sensitive] T) where for<'a> &'a T: fmt::Display + fmt::Debug;

#[derive(SensitiveDisplay)]
#[error("{0:?} {0}")]
struct TupleDebugFirst<T>(#[not_sensitive] T) where for<'a> &'a T: fmt::Display + fmt::Debug;

#[derive(Clone, serde::Serialize, SensitiveDual)]
#[error("{value} {value:?}")]
struct Dual<T> where for<'a> &'a T: fmt::Display + fmt::Debug {
    #[not_sensitive]
    value: T,
}

#[derive(Clone, serde::Serialize, SensitiveDual)]
#[error("{value:?} {value}")]
struct DualDebugFirst<T> where for<'a> &'a T: fmt::Display + fmt::Debug {
    #[not_sensitive]
    value: T,
}

// These impls overlap if borrowed formatting makes the generated impls unconditional.
trait NoProducer {}
impl<T: ToRedacted> NoProducer for T {}
impl NoProducer for Display<RefOnly> {}
impl NoProducer for Debug<RefOnly> {}
impl NoProducer for Both<RefOnly> {}
impl NoProducer for Both<DisplayOnly> {}
impl NoProducer for Both<DebugOnly> {}
impl NoProducer for Dual<RefOnly> {}
impl NoProducer for NamedDisplayFirst<DisplayOnly> {}
impl NoProducer for NamedDisplayFirst<DebugOnly> {}
impl NoProducer for NamedDebugFirst<DisplayOnly> {}
impl NoProducer for NamedDebugFirst<DebugOnly> {}
impl NoProducer for TupleDisplayFirst<DisplayOnly> {}
impl NoProducer for TupleDisplayFirst<DebugOnly> {}
impl NoProducer for TupleDebugFirst<DisplayOnly> {}
impl NoProducer for TupleDebugFirst<DebugOnly> {}
impl NoProducer for Dual<DisplayOnly> {}
impl NoProducer for Dual<DebugOnly> {}
impl NoProducer for DualDebugFirst<DisplayOnly> {}
impl NoProducer for DualDebugFirst<DebugOnly> {}

trait NoFormatter {}
impl<T: RedactableWithFormatter> NoFormatter for T {}
impl NoFormatter for Display<RefOnly> {}
impl NoFormatter for Debug<RefOnly> {}
impl NoFormatter for Both<RefOnly> {}
impl NoFormatter for Dual<RefOnly> {}

trait NoDeclaration {}
impl<T: DeclaredFormatting> NoDeclaration for T {}
impl NoDeclaration for Display<RefOnly> {}
impl NoDeclaration for Debug<RefOnly> {}
impl NoDeclaration for Both<RefOnly> {}
impl NoDeclaration for Dual<RefOnly> {}

trait NoDebug {}
impl<T: fmt::Debug> NoDebug for T {}
impl NoDebug for Display<RefOnly> {}
impl NoDebug for Debug<RefOnly> {}
impl NoDebug for Both<RefOnly> {}
impl NoDebug for Dual<RefOnly> {}

#[cfg(feature = "slog")]
trait NoSlog {}
#[cfg(feature = "slog")]
impl<T: redactable::slog::SlogRedacted> NoSlog for T {}
#[cfg(feature = "slog")]
impl NoSlog for Display<RefOnly> {}

#[cfg(feature = "tracing")]
trait NoTracing {}
#[cfg(feature = "tracing")]
impl<T: redactable::tracing::TracingRedacted> NoTracing for T {}
#[cfg(feature = "tracing")]
impl NoTracing for Display<RefOnly> {}

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct Override<T> where for<'a> &'a T: fmt::Display {
    #[not_sensitive]
    #[redactable(recursive)]
    value: T,
}

fn main() {
    assert_eq!(format!("{:?}", Display { value: 7 }), "7");
    assert_eq!(format!("{:?}", Debug(7)), "7");
    assert_eq!(format!("{:?}", Both::Named { value: 7 }), "7 7");
    assert_eq!(format!("{:?}", Both::Tuple(7)), "7 7");
    assert_eq!(format!("{:?}", NamedDisplayFirst { value: 7 }), "7 7");
    assert_eq!(format!("{:?}", NamedDebugFirst { value: 7 }), "7 7");
    assert_eq!(format!("{:?}", TupleDisplayFirst(7)), "7 7");
    assert_eq!(format!("{:?}", TupleDebugFirst(7)), "7 7");
    assert_eq!(format!("{:?}", Dual { value: 7 }), "7 7");
    assert_eq!(format!("{:?}", DualDebugFirst { value: 7 }), "7 7");
    let _ = NamedDisplayFirst { value: 7 }.to_redacted();
    let _ = NamedDebugFirst { value: 7 }.to_redacted();
    let _ = TupleDisplayFirst(7).to_redacted();
    let _ = TupleDebugFirst(7).to_redacted();
    let _ = Dual { value: 7 }.to_redacted();
    let _ = DualDebugFirst { value: 7 }.to_redacted();
    assert_eq!(format!("{:?}", Override { value: RefOnly }), "public");
    let _ = Override { value: RefOnly }.to_redacted();
}
