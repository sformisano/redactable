# Changelog

## 0.9.0

`Redactable` is now the certification trait, replacing the `DeclaredRedactable`
marker introduced in 0.8.0. One trait now carries both meanings: "this type has
declared redaction behavior" and "this type can be redacted".

### Changed
- **Breaking:** `Redactable` is no longer blanket-implemented over the traversal
  machinery. It is implemented by the `Sensitive`, `NotSensitive`, and
  `NotSensitiveDisplay` derives, by `SensitiveValue` / `NotSensitiveValue` and
  `serde_json::Value`, and forwarded through std containers of such types -
  never by bare leaves. `password.redact()` on a raw `String` no longer
  compiles: it was a no-op that read like a security action. Unannotated
  fields inside derived containers are unaffected (traversal uses the internal
  machinery, not `Redactable`).
- **Breaking:** the redacted-output extension traits (`RedactedOutputExt`,
  `RedactedJsonExt`, `SlogRedactedExt`) require plain `Redactable` again; the
  display-side gate (`SlogRedactedDisplayExt`, `RedactedDisplayValue`) requires
  `ToRedactedOutput`, which the display derives generate. Manual
  `RedactableWithMapper` implementors that opted into 0.8.0's
  `DeclaredRedactable` should implement `Redactable` instead.
- `tracing_redacted_valuable()` now also rejects raw values: it bounds on
  `Redactable`, which raw leaves no longer satisfy.

### Added
- `NotSensitiveDisplay` generates `ToRedactedOutput` (the `Display` text), so
  explicitly non-sensitive display types keep `slog_redacted_display()` and
  gain `tracing_redacted()`.

### Removed
- **Breaking:** the `DeclaredRedactable` marker trait. Its role is folded into
  `Redactable` (structural side) and `ToRedactedOutput` (display side).

## 0.8.0

Security-hardening release driven by a full-crate audit. Several fixes close
paths where sensitive data could reach logs unredacted; most are breaking.

### Fixed
- **Breaking:** keep-based policies (`Token`, `CreditCard`, `PhoneNumber`, `Pii`,
  `IpAddress`, `BlockchainAddress`) now fail closed: values at or below the keep
  window are fully masked instead of returned unchanged. A 4-character token
  under `Token` previously passed through `redact()`, `Debug`, and the logging
  integrations in clear text. The `Email` policy applies the same rule to short
  local parts.
- **Breaking:** the unredacted-`Debug` switch is now namespaced to this crate.
  Generated `Debug` impls branch on `cfg!(test) || redactable::__TESTING`
  instead of `#[cfg(any(test, feature = "testing"))]`, which resolved in the
  consumer's crate: enabling `redactable/testing` was a no-op, and a downstream
  crate with its own feature named `testing` silently got raw `Debug` output in
  production builds. All field types now need `Debug` in every build mode, not
  only under test.
- Variant-level `#[sensitive(...)]` and `#[not_sensitive]` on enums are rejected
  at compile time. They were silently ignored, so a variant that looked
  protected leaked its fields through `redact()`, `Debug`, and
  `redacted_display()`.
- `#[sensitive(dual)]` with only one of the two derives is now a compile error
  naming the missing counterpart. It previously compiled while silently
  dropping the redacted `Debug` impl (Sensitive-only) or the slog/tracing
  integration (SensitiveDisplay-only).
- IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`, the standard dual-stack
  representation of IPv4 clients) redact with the IPv4 rule. The plain IPv6
  rule kept the last 16-bit segment, which holds the last two octets of the
  embedded IPv4 address.
- The email policy splits on the last `@` instead of the first, so RFC-quoted
  local parts containing `@` no longer leak into the preserved domain segment.

### Added
- `DeclaredRedactable`: a marker trait for types whose redaction behavior is
  explicitly declared. Emitted by the `Sensitive`, `NotSensitive`,
  `NotSensitiveDisplay`, and `SensitiveDisplay` derives, implemented by
  `SensitiveValue`, `NotSensitiveValue`, and `serde_json::Value`, and forwarded
  through std containers.
- **Breaking:** `RedactedOutputExt`, `RedactedJsonExt`, `SlogRedactedExt`, and
  `SlogRedactedDisplayExt` now require `DeclaredRedactable`. Raw passthrough
  values (`String`, scalars, containers of them) previously satisfied these
  blanket impls as no-ops, so `password.redacted_output()` compiled, performed
  zero redaction, and carried the `SlogRedacted`/`TracingRedacted`
  certification markers.
- `rust-version = "1.93"` declared in both crates; CI tests on current stable
  with a dedicated MSRV check job.
- docs.rs builds with all features, so the `slog`, `tracing`, `json`, and
  `extras` APIs appear in the rendered documentation.

### Changed
- **Breaking:** `RedactedOutput` is `#[non_exhaustive]`. The `Json` variant is
  feature-gated, and feature unification meant an exhaustive downstream match
  could stop compiling when another crate enabled `json`.
- `redactable` now pins `redactable-derive` with an exact `=` requirement so
  the runtime/derive pair always resolves together.
- `RedactableWithFormatter` and `RedactedFormatterRef` are documented public
  API. They were `#[doc(hidden)]` even though `.redacted_display()` - the
  flagship `SensitiveDisplay` method - lives on the trait.

### Documentation
- README quick-start examples now compile as written: missing trait and policy
  imports added, and the display assertion goes through `.to_string()`.
- The wrapper-type example defines a local policy, matching the orphan-rule
  requirement the surrounding text describes.
- Documented the `chrono`, `time`, `uuid`, and `extras` features, the
  fail-closed short-value rule, the per-field attribute rule for enums, the
  IPv4-mapped IPv6 behavior, and the `DeclaredRedactable` certification gate.
- Fixed section links that pointed at a non-existent anchor.

## 0.7.1

### Fixed
- Narrowed the logging-safe `ToRedactedOutput` boundary so raw passthrough values like `String`
  no longer qualify as redacted output without an explicit wrapper or derived container.
- Made `SensitiveDisplay` policy formatting work for redacted containers such as `Option<String>`
  and `Vec<String>` in `{field}` templates.
- Restored IP address handling to the opt-in model. Unannotated IP address fields pass through
  unchanged, while `#[sensitive(IpAddress)]` still redacts them.
- Made the `ip-address` feature enable the redaction surface it depends on.
- Added clearer compile-time errors for sparse positional templates, unsupported format syntax,
  and `NonZero*` fields annotated with redaction policies.
- Removed `json`-only dead-code warnings from the `RedactedJson` internals.

### Documentation
- Documented the `serde_json::Value` default-redact exception, raw serialization behavior for
  `SensitiveValue`, derived `Debug` placeholder behavior, empty string redaction, and supported
  `SensitiveDisplay` format syntax.

## 0.7.0

### Added
- `#[sensitive(dual)]` container attribute for types that derive both `Sensitive` and
  `SensitiveDisplay`. Both macros read this attribute and coordinate: `Sensitive` skips `Debug`
  (letting `SensitiveDisplay` provide it), and `SensitiveDisplay` skips `slog`/`tracing`
  (letting `Sensitive` provide them). Each macro generates only its non-overlapping impls.

### Removed
- **Breaking:** `#[sensitive(skip_debug)]` container attribute. The only container-level option
  is now `#[sensitive(dual)]`.
- `#[sensitive_display(only)]` container attribute (superseded by `#[sensitive(dual)]`).
- `SensitiveDisplay` no longer generates a `RedactableWithMapper` impl (reverted from 0.6.1).
  Newtypes that need structural redaction inside `Sensitive` containers should derive `Sensitive`
  directly.

## 0.6.1

### Fixed
- Suppress unused variable warnings for `#[sensitive(Policy)]` fields in the generated redacted
  `Debug` impl. The redacted debug destructure pattern now uses wildcard bindings (`field: _` for
  named fields, `_` for tuple fields) for sensitive fields instead of creating unused bindings.
  The `#[allow(unused_variables)]` attribute on the redacted `Debug` impl has been removed since
  it is no longer needed.

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
