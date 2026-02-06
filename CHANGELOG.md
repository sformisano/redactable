# Changelog

## 0.5.1 - 2026-02-06

### Fixed
- `NotSensitiveDisplay` now always delegates to `Display::fmt`, ignoring display templates (doc comments, `#[error("...")]`). Previously, detected templates caused the derive to parse placeholders and require fields to implement `RedactableDisplay`, which broke types with foreign field types (e.g. `anyhow::Error`, `std::io::Error`).
- `#[not_sensitive]` attributes on `NotSensitiveDisplay` fields are now rejected with a clear error message (the entire type is already non-sensitive).

## 0.5.0 - 2026-02-05

### Added
- `NotSensitiveDisplay` derive macro for types with no sensitive data that need logging integration
  - Provides symmetry with `SensitiveDisplay`: generates `RedactableDisplay`, `Debug`, `slog::Value`, `SlogRedacted`, and `TracingRedacted`
  - Requires `T: Display` and delegates `RedactableDisplay` to the existing `Display` implementation
  - Supports `#[not_sensitive_display(skip_debug)]` attribute to opt out of `Debug` impl generation
  - Also generates `RedactableContainer` impl (no-op passthrough), so types can be used inside `#[derive(Sensitive)]` containers without also deriving `NotSensitive`
- `NotSensitive<T>` wrapper and `.not_sensitive()` escape hatch with no formatting preference
- `NotSensitive<T>` implements `slog::Value` when `T: slog::Value` and `SlogRedacted`/`TracingRedacted` when the inner type does
- `.not_sensitive_display()` for explicit `Display` formatting at logging boundaries
- Conditional `Debug` impl for `SensitiveDisplay` (redacted in production, unredacted in tests)

### Fixed
- `PhantomData<T>` fields no longer require `T: RedactableContainer` bound; they are automatically
  treated as passthrough without the need for `#[not_sensitive]` annotation

### Breaking
- `.not_sensitive()` no longer implies `Display` formatting; use `.not_sensitive_display()` for
  text output or `.not_sensitive_debug()` for `Debug` formatting

## 0.4.0 - 2026-02-05

### Added
- `serde_json::Value` support: `Value` is now treated as an opaque leaf type that fully redacts to `Value::String("[REDACTED]")` on any policy application
- Implementations for `PolicyApplicable`, `PolicyApplicableRef`, `RedactableContainer`, and `RedactableDisplay` for `serde_json::Value` (behind `json` feature flag)
- Safe-by-default behavior: unannotated `Value` fields in `#[derive(Sensitive)]` structs are fully redacted
- Support for nested types like `Option<Value>`, `Vec<Value>`, `HashMap<K, Value>`, etc.

## 0.3.0 - 2026-02-05

### Added
- `#[not_sensitive]` attribute now supported on `Sensitive` derive macro (previously only `SensitiveDisplay`)
- Both derive macros now have consistent field annotation options: `#[sensitive(Policy)]` and `#[not_sensitive]`

### Changed
- `#[not_sensitive]` attribute provides an alternative to `NotSensitiveValue<T>` wrapper for foreign types

### Removed
- `SensitiveData` derive macro alias (use `Sensitive` instead)

## 0.2.0 - 2026-02-04

### Added
- `SensitiveDisplay` derive for template-based redacted formatting (thiserror/displaydoc style)
- `#[not_sensitive]` attribute for explicit opt-out in `SensitiveDisplay` templates
- `PolicyApplicableRef` trait for reference-based policy application (no Clone required)
- `apply_policy_ref` function for reference-based redaction
- slog support for `SensitiveValue<T, P>` where T implements `RedactableWithPolicy`
- Supply chain checks in CI (cargo-audit, cargo-deny)

### Changed
- `SensitiveDisplay` requires explicit annotation for every field in templates
- `SensitiveDisplay` no longer requires `Clone` for policy-annotated fields
- `HashMap`/`HashSet` policy application now uses `BuildHasher + Default` instead of `Clone`
- Serialization error fallbacks now include error details

### Removed
- `SensitiveError` (use `SensitiveDisplay` instead)
- `Error` policy marker
- `RedactableError` renamed to `RedactableDisplay`
