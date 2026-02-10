# Changelog

## 0.6.1

### Added
- `SensitiveDisplay` now generates a `RedactableWithMapper` impl that walks inner fields and
  applies redaction — the same traversal logic used by `Sensitive`. This allows `SensitiveDisplay`
  types to be used as fields inside `#[derive(Sensitive)]` containers and ensures their sensitive
  data is properly redacted when `.redact()` is called on a parent struct.

## 0.6.0

### Changed (BREAKING)
- Renamed `RedactableContainer` to `RedactableWithMapper`
- Renamed `RedactableDisplay` to `RedactableWithFormatter`
- Renamed `RedactedDisplayRef` to `RedactedFormatterRef`
- Renamed `RedactableWithPolicy` to `SensitiveWithPolicy`
- Removed `RedactableLeaf` trait (its functionality is now covered by `SensitiveWithPolicy`)
- All `Redactable*` internal traits are now consistently `#[doc(hidden)]`

## 0.5.3 - 2026-02-06

### Added
- `NotSensitive` derive now generates `slog::Value` / `SlogRedacted` and `TracingRedacted`
  implementations, giving it logging parity with `Sensitive`. The slog integration serializes
  the value directly as structured JSON (requires `Serialize` on the type, same as `Sensitive`).
- `#[sensitive]` and `#[not_sensitive]` attributes on `NotSensitive` types (container or field level)
  are now rejected with clear errors - the former because the type is explicitly non-sensitive,
  the latter because it is redundant.
- Bare `#[sensitive]` on derive macro containers is now rejected with a clear error instead of
  being silently ignored.

### Removed
- `NotSensitiveDisplay` no longer generates a `Debug` impl. Like `NotSensitive`, there is nothing
  to redact - use `#[derive(Debug)]` instead. The `#[not_sensitive_display(skip_debug)]` attribute
  has been removed accordingly.

## 0.5.1 - 2026-02-06

### Fixed
- `NotSensitiveDisplay` now always delegates to `Display::fmt`, ignoring display templates (doc comments, `#[error("...")]`). Previously, detected templates caused the derive to parse placeholders and require fields to implement `RedactableWithFormatter`, which broke types with foreign field types (e.g. `anyhow::Error`, `std::io::Error`).
- `#[not_sensitive]` attributes on `NotSensitiveDisplay` fields are now rejected with a clear error message (the entire type is already non-sensitive).

## 0.5.0 - 2026-02-05

### Added
- `NotSensitiveDisplay` derive macro for types with no sensitive data that need logging integration
  - Provides symmetry with `SensitiveDisplay`: generates `RedactableWithFormatter`, `slog::Value`, `SlogRedacted`, and `TracingRedacted`
  - Requires `T: Display` and delegates `RedactableWithFormatter` to the existing `Display` implementation
  - Also generates `RedactableWithMapper` impl (no-op passthrough), so types can be used inside `#[derive(Sensitive)]` containers without also deriving `NotSensitive`
- `NotSensitive<T>` wrapper and `.not_sensitive()` escape hatch with no formatting preference
- `NotSensitive<T>` implements `slog::Value` when `T: slog::Value` and `SlogRedacted`/`TracingRedacted` when the inner type does
- `.not_sensitive_display()` for explicit `Display` formatting at logging boundaries
- Conditional `Debug` impl for `SensitiveDisplay` (redacted in production, unredacted in tests)

### Fixed
- `PhantomData<T>` fields no longer require `T: RedactableWithMapper` bound; they are automatically
  treated as passthrough without the need for `#[not_sensitive]` annotation

### Breaking
- `.not_sensitive()` no longer implies `Display` formatting; use `.not_sensitive_display()` for
  text output or `.not_sensitive_debug()` for `Debug` formatting

## 0.4.0 - 2026-02-05

### Added
- `serde_json::Value` support: `Value` is now treated as an opaque leaf type that fully redacts to `Value::String("[REDACTED]")` on any policy application
- Implementations for `PolicyApplicable`, `PolicyApplicableRef`, `RedactableWithMapper`, and `RedactableWithFormatter` for `serde_json::Value` (behind `json` feature flag)
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
- slog support for `SensitiveValue<T, P>` where T implements `SensitiveWithPolicy`
- Supply chain checks in CI (cargo-audit, cargo-deny)

### Changed
- `SensitiveDisplay` requires explicit annotation for every field in templates
- `SensitiveDisplay` no longer requires `Clone` for policy-annotated fields
- `HashMap`/`HashSet` policy application now uses `BuildHasher + Default` instead of `Clone`
- Serialization error fallbacks now include error details

### Removed
- `SensitiveError` (use `SensitiveDisplay` instead)
- `Error` policy marker
- `RedactableError` renamed to `RedactableDisplay` (now `RedactableWithFormatter` as of 0.6.0)
