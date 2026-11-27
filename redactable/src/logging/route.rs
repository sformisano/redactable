use std::{fmt, sync::OnceLock};

#[cfg(feature = "slog")]
use ::slog::Logger as SlogLogger;
#[cfg(not(feature = "slog"))]
use std::convert::Infallible as SlogLogger;

static SINK: OnceLock<Sink> = OnceLock::new();

/// The backend for a checked logging event.
///
/// Use [`set_sink`] to choose a backend for the application or pass `sink:`
/// to a checked macro for a single event. Each backend has its own Cargo feature.
#[derive(Clone, Debug)]
#[non_exhaustive]
#[allow(missing_copy_implementations)] // The slog variant owns its logger.
pub enum Sink {
    /// The application's global `log` logger.
    #[cfg(feature = "log")]
    Log,
    /// The active `tracing` subscriber.
    #[cfg(feature = "tracing")]
    Tracing,
    /// A `slog` logger with its configured drain and context.
    #[cfg(feature = "slog")]
    Slog(SlogLogger),
}

/// The application has already selected a sink with [`set_sink`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetSinkError(());

impl fmt::Display for SetSinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the checked logging sink has already been set")
    }
}

impl std::error::Error for SetSinkError {}

/// Selects the process-wide backend for checked logging. The application configures
/// the logger or subscriber through the backend's own API.
///
/// Before registration, calls without a `sink:` argument use native `log` when
/// its feature is enabled. With `log` disabled, those calls begin emitting
/// events after registration.
///
/// # Errors
///
/// Returns [`SetSinkError`] if a previous call installed a sink. The first
/// successful call determines the process-wide backend.
pub fn set_sink(sink: Sink) -> Result<(), SetSinkError> {
    SINK.set(sink).map_err(|_| SetSinkError(()))
}

// Downstream macro expansions match the same variants across feature sets.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub enum Route<'a> {
    Log,
    Tracing,
    Slog(&'a SlogLogger),
    Disabled,
}

impl Sink {
    #[doc(hidden)]
    pub fn route(&self) -> Route<'_> {
        match self {
            #[cfg(feature = "log")]
            Self::Log => Route::Log,
            #[cfg(feature = "tracing")]
            Self::Tracing => Route::Tracing,
            #[cfg(feature = "slog")]
            Self::Slog(logger) => Route::Slog(logger),
        }
    }
}

#[doc(hidden)]
pub fn __default_route() -> Route<'static> {
    match SINK.get() {
        Some(sink) => sink.route(),
        None if cfg!(feature = "log") => Route::Log,
        None => Route::Disabled,
    }
}
