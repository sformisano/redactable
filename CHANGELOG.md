# Changelog

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
