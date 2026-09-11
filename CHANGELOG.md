# Changelog

## 0.13.0 - 2026-09-12

### Breaking

- `Sensitive`, `SensitiveDisplay`, and `SensitiveDual` now check required field
  operations at the type definition, even when no method is called. Generic
  declarations must state their field capabilities. Unannotated structural
  fields require `Redactable`; policy-marked template fields use
  `PolicyDisplay<P>`, `PolicyDebug<P>`, or both. This closes the generated
  `Sensitive` Debug path that could print an undeclared generic payload.

### Fixed

- Generic policy formatting supports the same Secret scalars and bare IP types
  as concrete fields, including socket addresses with their ports preserved.
- A distinct type such as `self::other::Node<T>` is no longer mistaken for the
  enclosing `Node<T>` when generating recursive bounds.
- `.slog_redacted_json()` and `.tracing_redacted()` accept unsized `ToRedacted`
  producers, including trait objects. `.slog_redacted()` still requires `Sized`.

### Documentation

- The Valuable adapter documentation now describes borrowed inner projections.
  Caller-driven mutation through those projections can affect later output.
  The adapter redacts its contents when constructed.

## 0.12.1 - 2026-09-11

### Changed

- Refreshed repository automation dependencies.

### Documentation

- Includes the revised README in the crates.io package.

## 0.12.0 - 2026-09-07

### Breaking

- Sensitive derives now require declared redaction behavior on default fields.
  Raw leaves need a policy or explicit `#[not_sensitive]`; supported containers
  check their contents. `SensitiveDisplay` checks only template references,
  while `SensitiveDual` checks every structural field. Manual formatters can
  declare their formatting behavior with `__private::DeclaredFormatting`.
- The derive decides the logging output and always generates it, so `Sensitive`
  and `SensitiveDual` now require `Clone + Serialize` and `NotSensitive`
  requires `Serialize` in every configuration. `Sensitive` produces redacted
  JSON, `SensitiveDisplay` redacted template text, `SensitiveDual` both, and the
  two non-sensitive derives the raw value their author declared public. A
  derived type owns that implementation, so a handwritten one for the same type
  now conflicts with the generated one; a projection that must select different
  fields or summary text belongs on a dedicated log-view type.
- `RedactedOutput` is renamed `RedactedValue`, and
  `ToRedactedOutput::to_redacted_output` is renamed `ToRedacted::to_redacted`.
  The value is opaque: the `Text` and `Json` variants are gone, along with every
  raw construction route and the arbitrary hidden JSON factory. The derives
  build their values through doc-hidden helpers that redact or serialize a
  declared type themselves, and the borrowed slog route keeps its zero-argument
  fixed placeholder. Read it through two accessors that always answer. `text()`
  returns the redacted text, or the redacted JSON as compact text. `json()`
  returns the redacted JSON, or `{"message": text}` for a text-only value, where
  0.11 produced a bare JSON string. The producer's representation is built with
  the value; the other accessor converts it on each call and never reruns a
  policy.
- No `RedactedValue` is lazy: `to_redacted()` builds an owned result and retains
  no reference to the source. The lazy bridges `RedactedJson`,
  `RedactedJsonRef`, `RedactedOutputRef` and the extension traits behind
  `.redacted_output()`, `.into_redacted_output()`, `.redacted_json()` and
  `.into_redacted_json()` are removed. JSON in hand is
  `value.to_redacted().json()`. Two borrowed adapters remain by design:
  `.slog_redacted()` holds a reference and runs the producer when slog
  serializes the record, and `.redacted_display()` is still a borrowed
  formatting view; `.slog_redacted_json()` runs the producer at the call and
  returns an owned value.
- Logging a structural value clones it. `to_redacted` borrows its receiver, and
  the `Sensitive` and `SensitiveDual` implementations clone, redact, then
  serialize, so 0.12 has no non-cloning route to a structural logging value: a
  traversed `RefCell` with a live mutable borrow panics at the log call, as the
  borrowing routes in 0.11 already did. The display derives format the borrowed
  value without `Clone`: `SensitiveDisplay` renders a mutably borrowed `RefCell`
  as `<borrowed>` through the crate's formatter, while `NotSensitiveDisplay`
  inherits the type's own `Display`; `NotSensitive` serializes the borrowed
  value. `.slog_redacted_json()` borrows
  instead of consuming. The consuming `into_tracing_redacted_debug` and
  `into_tracing_redacted_valuable` adapters are unchanged, and a borrowed
  `Sensitive` value still fails closed to `"[REDACTED]"` through the directly
  generated slog implementation.
- Containers of derived types keep `.redact()` but implement no `ToRedacted`
  of their own: a `Vec<T>` or `Option<T>` is not a logging value even when `T`
  is. Log a slice of producers through `RedactedList`, or wrap the
  already-redacted container in a `Bypass*` member.
- `Sensitive` containers holding `Arc<T>` or `Rc<T>` need serde's `rc` feature
  in the consuming crate, a handwritten `Serialize`, or `#[serde(skip)]` on that
  field, because serde does not implement `Serialize` for shared pointers by
  default and 0.12 requires `Serialize` on the container. This crate does not
  enable `serde/rc` for you.
- The explicit escapes are renamed for the redaction each one bypasses.
  `NotSensitiveValue` becomes `BypassRedaction`, the `NotSensitiveDisplay<T>`,
  `NotSensitiveDebug<T>` and `NotSensitiveJson<'_, T>` wrappers become
  `BypassDisplayRedaction<T>`, `BypassDebugRedaction<T>` and
  `BypassJsonRedaction<'_, T>`, and `NotSensitive<T>` becomes
  `BypassRedactionMarker<T>`. Their extension traits are removed: every member is
  built with tuple syntax, which is why `BypassJsonRedaction`'s field is now
  public. `BypassRedaction<T>` still does not implement `ToRedacted`. Two of
  these renames produce no unresolved import, because `NotSensitive` and
  `NotSensitiveDisplay` are also derive-macro names: an existing
  `use redactable::NotSensitiveDisplay;` still compiles, and the failure appears
  at the use site as `E0423` in value position or `E0573` in type position.
- `SlogRedactedDisplayExt::slog_redacted_display` is renamed
  `SlogRedactedExt::slog_redacted`, and `SlogRedactedExt` is bounded on
  `ToRedacted` instead of `Redactable + Serialize`. Both of its methods are
  therefore available on every producer, including a plain `Sensitive` struct
  that implements no formatter. `BypassRedaction<T>`, which deliberately
  implements no producer, loses `.slog_redacted_json()`; log it with
  `BypassJsonRedaction(&value)` instead.
- Generated `Debug` keeps production redaction in consumer tests and with the
  `testing` feature. The feature now enables test helpers without raw exposure.

### Added

- `RedactedValue::text()` and `RedactedValue::json()` read the logging value.
  Neither can refuse: a sink chooses the representation it wants and the value
  adapts, so custom pipelines no longer carry a branch for a representation they
  did not ask for.
- `BypassTextRedaction` records deliberately selected summary text, including
  empty summaries. It does not validate the summary's disclosure or
  completeness. With the renamed escapes listed under Migration it forms the
  `Bypass*` family, each member named for the redaction it bypasses.
- `RedactedList` produces item-limited JSON with an explicit `NonZeroUsize`
  limit and visible omitted count. Each included item is its `json()`, so a text
  item appears as `{"message": …}`. It runs only included producers and does
  not bound total bytes, depth, or policy cost.
- `testing::assert_json_shape`, with the `testing` feature, checks object keys,
  array positions, and scalar kinds with strict JSON Pointer opaque paths. It
  reads the value's `json()`, so a text-only producer is compared as
  `{"message": …}` rather than rejected. Expected policy values must still be
  checked independently.

### Changed

- The `redaction` feature now enables `serde` and `serde_json`, which the
  generated outputs need in every configuration. `json` is kept as a
  compatibility alias that enables `redaction`, so `--features json` selects
  exactly what it selected in 0.11. `--features redaction` and the default
  feature set now also link the serde stack; `--no-default-features` and
  `--features policy` are unaffected.

### Fixed

- The slog display adapter now renders what the producer selected,
  `to_redacted().text()`, instead of calling a potentially different formatter.
  Direct generated slog placeholders remain unchanged.

### Documentation

- Rewrote the README derive guide, wrapper guidance, and custom-pipeline section
  for the automatic outputs, the `Bypass*` family, and the mandatory `Clone` and
  `Serialize` bounds. Corrected the foreign-field guidance: a foreign field in a
  struct you own is declared with `#[not_sensitive]`, and `BypassRedaction<T>` is
  for a boundary that bounds the foreign value itself.
- Updated field-declaration migrations, output-boundary examples, Debug behavior,
  clone requirements, policy exceptions, and explicit public passthrough guidance.

### Migration from 0.11

Every public item this release removes or renames:

| 0.11 | 0.12 | Note |
|---|---|---|
| `RedactedOutput` | `RedactedValue` | Opaque: no `Text`/`Json` variants, no public construction, no `Deserialize` |
| `ToRedactedOutput` | `ToRedacted` | |
| `.to_redacted_output()` | `.to_redacted()` | Still borrows `&self` |
| `RedactedOutputExt::redacted_output()` | `.to_redacted()` | |
| `IntoRedactedOutputExt::into_redacted_output()` | `.to_redacted()` | No consuming route remains |
| `RedactedJsonExt::redacted_json()` | `.to_redacted().json()` | |
| `IntoRedactedJsonExt::into_redacted_json()` | `.to_redacted().json()` | No consuming route remains |
| `RedactedJson`, `RedactedJsonRef`, `RedactedOutputRef` | Removed | `RedactedValue` is the only logging value |
| `NotSensitiveValue<T>` | `BypassRedaction<T>` | For a field of a struct you own, prefer `#[not_sensitive]` on the field |
| `NotSensitiveDisplay<T>` (wrapper) | `BypassDisplayRedaction<T>` | The old name still resolves, to the derive macro: `E0423` or `E0573` at the use site, not an unresolved import |
| `NotSensitiveDebug<T>` | `BypassDebugRedaction<T>` | |
| `NotSensitiveJson<'_, T>` | `BypassJsonRedaction<'_, T>` | Field is now public; construct it as `BypassJsonRedaction(&value)` |
| `NotSensitive<T>` (wrapper) | `BypassRedactionMarker<T>` | Same derive-macro shadowing as `NotSensitiveDisplay` |
| `.not_sensitive()`, `.not_sensitive_display()`, `.not_sensitive_debug()`, `.not_sensitive_json()` | Tuple construction | The four extension traits are removed |
| `SlogRedactedDisplayExt::slog_redacted_display()` | `SlogRedactedExt::slog_redacted()` | Renders `to_redacted().text()` |
| `SlogRedactedExt::slog_redacted_json(self)` | `.slog_redacted_json(&self)` | Returns a JSON-only `RedactedValue`; the emitted bytes are unchanged |
| `#[redactable(output = json)]` | Removed | The option existed only inside this unreleased line; `Sensitive` and `SensitiveDual` always produce JSON, and the derive rejects the attribute with a migration message |

Behavior that changed without changing a name:

- `Sensitive` and `SensitiveDual` require `Clone + Serialize`, and
  `NotSensitive` requires `Serialize`, in every feature configuration.
- `Sensitive` and `NotSensitive` now always implement `ToRedacted`.
  `SensitiveDual` carries text and JSON in one value and builds both on every
  call, where 0.11 built only the template.
- `json()` on a text-only value yields `{"message": text}` instead of a bare
  JSON string. This changes structured captures of a display-only producer and
  the encoding of text items inside `RedactedList`.
- `RedactedValue`'s `Debug` shows the stored redacted representations; it is no
  longer the 0.11 enum-style output.
- `redaction` now pulls in `serde` and `serde_json`, and `json` is a
  compatibility alias of `redaction`.

Unchanged: the five derive names, `#[not_sensitive]`, `#[sensitive(Policy)]`,
`#[redactable(recursive)]`, `legacy_formatting`, `generated_formatting`,
same-type `.redact()`, `.redacted_display()`, raw Serde transport, scalar
defaults, map keys, set collapse, `PhantomData`, recursive support, the tracing
representations, and the directly generated slog placeholder.

## 0.11.0 - 2026-07-19

### Breaking

- Replace `#[derive(Sensitive, SensitiveDisplay)]` with
  `#[derive(SensitiveDual)]` and remove `#[sensitive(dual)]`. The legacy form
  now fails with a migration diagnostic; the single derive generates both
  behaviors through one authenticated entry point that downstream code cannot
  imitate to suppress redacted `Debug`.
- Custom `RedactionPolicy` implementations must now declare their structural
  kind. Existing text policies should add `type Kind = TextPolicyKind;` and
  import `TextPolicyKind` from `redactable`.
- Redactable 0.11 requires Rust 1.97. CI follows the latest stable compiler and
  no longer maintains a separate older-compiler compatibility job.
- The tracing Valuable wrapper `RedactedValuable` is renamed to
  `TracingRedactedValue`, its redacted contents are read through the consuming
  `into_inner(self)` instead of a borrowing `inner(&self)`, and it is no longer
  `Clone`. A clone would hand out a second handle to shared interior-mutable
  inner state, letting a caller insert a fresh secret after redaction and have
  the original wrapper log it.
- `PolicyApplicableRef` for `RefCell<T>` again uses
  `Output = RefCell<T::Output>`, restoring the public contract from 0.10.0.
  Code that depended specifically on the 0.10.1 `PolicyRefCellOutput`
  association must update; generated formatting still emits `<borrowed>` on a
  conflicting mutable borrow through a separate internal route.
- Custom `PolicyApplicableRef` types used by `SensitiveDisplay` must now also
  implement the formatting companion trait. For a leaf that should retain the
  legacy behavior, add
  `impl redactable::__private::PolicyApplicableRefForFormatting for MyType {}`.
  The companion is an empty marker; library-owned recursive formatting uses a
  separate internal capability to propagate nested borrow conflicts.
- Direct generic calls to the legacy `PolicyApplicable::apply_policy` and
  `PolicyApplicableRef::apply_policy_ref` methods must prove
  `P::Kind: RecursivePolicyKind`. Generic code that may receive an IP policy
  should use the kind-aware `apply_policy` or `apply_policy_ref` free function.
  `PolicyApplicableRef::apply_policy_ref` and the `apply_policy_ref` free
  function use ordinary `RefCell` borrowing and panic if a traversed `RefCell`
  is mutably borrowed. Generated `SensitiveDisplay` formatting renders
  `<borrowed>` instead.
- `SlogRedactedExt` no longer has a `Debug` supertrait. Generic code that used
  `T: SlogRedactedExt` as proof of `T: Debug` must add an explicit `Debug`
  bound. Types implementing `Redactable + Serialize` can call
  `.slog_redacted_json()` without implementing `Debug`.

### Removed

- Removed repository scripts that rewrote authorship, commit trailers, and tags.

### Documentation

- Corrected the README's clone-based output and tracing adapter bounds by
  removing the proposed `RefUnwindSafe` compatibility gate.
- Made the exact `PaymentEvent` slog example part of the standalone README
  consumer doctest suite.
- Documented the existing E0509 limitation when a `Sensitive` container itself
  implements `Drop`, and clarified that every such container is unsupported,
  including Copy-only shapes and `SensitiveDual`. Fields with their own drop
  behavior remain supported inside containers that do not implement `Drop`.
- Clarified that clone-free map formatting applies to the generated text/secret
  recursive route; IP-policy maps rebuild an owned projection and clone allowed
  keys and `HashMap` hashers. Corrected container traversal wording and
  documented `SensitiveValue` policy precedence and the testing-feature risk.
- Corrected the ambiguous `SensitiveValue::from("...".into())` example and
  documented the `nested-values` feature required by downstream slog drains.

### Fixed

- Release publication now verifies identity, not just a version number. An
  existing crates.io version is only accepted as "already published" when its
  checksum matches the archive this release just packaged and inspected, and a
  yanked version is refused outright. Previously a retry could skip publishing
  `redactable-derive` because the version number existed, then publish
  `redactable` against a derive built from different source - permanently, since
  crates.io is immutable and the runtime pins the derive with `=`.
- The immutable-action guard now catches every YAML form a `uses:` key can take,
  including the inline list item (`- uses: x@tag`) and flow style
  (`- { uses: x@tag }`), and scans composite actions under `.github/actions`.
  It previously matched only line-start `uses:`, so the other forms passed
  silently. The guard now has mutant tests of its own, run in CI.
- `cargo-audit` and `cargo-deny` are pinned to reviewed versions in CI, so a
  supply-chain gate cannot change underneath a release without review.
- The consuming tracing Valuable adapter is now exercised end-to-end through a
  real subscriber and visitor with a canary, rather than only inspecting the
  redacted value through `inner()`.
- The panic-abort fixture now carries a locked dependency graph and can fetch
  it before exercising its subprocesses, so the standard workspace test
  command works with an empty Cargo cache. CI verifies that clean-cache path.
- Compile-fail coverage now protects both halves of the tracing Valuable
  wrapper invariant: the wrapper is neither cloneable nor borrowable through
  an `inner()` method.

- Added consuming output, JSON, tracing Debug, and tracing Valuable adapters.
  Each redacts the owned value through `.redact()` rather than cloning it first,
  so a live `RefCell` mutable borrow no longer panics on these routes. (`.redact()`
  itself may still clone internally — an `Arc`/`Rc` referent, or a `HashMap`/
  `HashSet` hasher.) They
  accept every `Redactable` shape, including types using
  `#[redactable(recursive)]`. Traversal through `Arc` or `Rc` still clones the
  shared referent because another owner may hold it, so a live `RefCell` mutable
  borrow behind an `Arc`/`Rc` can still panic. Prefer unique ownership (`Box`)
  for values you log; `Arc<RefCell<T>>` is `!Send + !Sync` and an anti-pattern
  regardless. Retained borrowed clone-based adapters now document their panic
  behavior for live `RefCell` mutable borrows.
- Removed the owned-capability trait hierarchy that briefly backed those
  adapters (`CloneFreeRedactable` and its supporting traits). It duplicated the
  traversal `.redact()` already performed, and its only real effect was to
  reject `Arc`/`Rc` statically. That guarantee was not worth its cost: the
  generated capability leaked the derived type's field types into a public
  associated type, so a `pub` type holding a private field type failed to
  compile with `error[E0446]: private type ... in public interface`. Deleting
  the hierarchy fixes that regression and makes recursive types work through the
  consuming adapters. Code naming `CloneFreeRedactable` in a bound should drop
  it; no other source change is needed.
- Pinned every third-party verification/release action to an immutable commit,
  disabled persisted checkout credentials, added Dependabot updates and an
  immutable-reference check, and extended CI to strict-rustdoc every isolated
  feature.
- Generic policy parameters on concrete scalar and typed-IP
  `SensitiveDisplay` fields now use the selected policy-kind capability instead
  of requiring the field to be a generated recursive container. The Syn
  spelling classifier was removed: alias-hidden or otherwise ambiguous
  library-owned containers select their route explicitly with
  `#[redactable(generated_formatting)]`, preserving legal downstream empty-marker
  specialization on stable Rust.
- Misplaced field-only helper attributes now fail with direct diagnostics, and
  stable rustfmt no longer loads ignored nightly-only settings.
- Generated borrowed slog output no longer serializes raw values as a safety
  preflight. It fails closed without invoking user serializers; owned
  `.slog_redacted_json()` redacts through `.redact()` like the JSON,
  redacted-output, and tracing consuming adapters.
- Recursive derives no longer repeat recognized direct self-referential field
  predicates. `#[redactable(recursive)]` provides an explicit bound override for
  crate-qualified, alias-hidden, and mutually recursive generic fields without
  weakening complete-type bounds on unrelated fields. It composes with
  `legacy_formatting`: cyclic field bounds remain suppressed while the required
  reference projection and output-format bounds remain present.
- Text/secret recursive policy formatting is compositionally closed for sets of maps, borrows map keys
  and hashers without `Clone`, invokes exactly the requested compact or alternate
  Debug mode once per key, and resolves `&str` aliases through trait behavior
  rather than syntax.
- Restored empty downstream `PolicyApplicableRefForFormatting` implementations.
  Custom leaves nested in containers can opt into their ordinary
  `PolicyApplicableRef` projection with `#[redactable(legacy_formatting)]`, while
  the default library-owned route remains clone-free and borrow-conflict safe.
  The empty marker is required only for automatic direct custom-leaf dispatch;
  the explicit route instead requires `PolicyApplicableRef` and the selected
  output-format bound. Standalone `Sensitive` rejects the display-only option;
  `SensitiveDual` supports it.
- Made `NotSensitiveDebug<T>` transparently delegate to the inner `Debug` output.
- `IpAddress` policy dispatch is now type-directed after generic substitution,
  so aliases and generic policy parameters cannot bypass IP container checks.
  Raw typed IP values remain bare-field-only; recursive containers accept text
  leaves and `SensitiveValue<_, IpAddress>`, and maps preserve keys only when
  the key type is on the sealed safe-key allowlist.
- Explicitly non-sensitive JSON and generated slog serialization now use a
  fixed `"[REDACTED]"` JSON string on serialization failure without exposing
  serializer errors or input data.
- `NotSensitive<T>` now provides slog and tracing certification while leaving
  the unwrapped raw type uncertified.
- Derive-generated identifiers are allocated without colliding with user
  fields, variants, type parameters, const parameters, or lifetimes.
- Generated policy formatting preserves the public `RefCell` output type and,
  for library-owned recursive formatting implementations, propagates borrow
  conflicts as `<borrowed>` without panicking, including with `panic = "abort"`.
- Documentation, CI coverage, and compiler-diagnostic snapshots now match the
  supported APIs and Rust 1.97 output.

## 0.10.1 - 2026-07-13

### Added
- `NotSensitiveDebug<T>` and `NotSensitiveDisplay<T>` now support owned-value
  extraction with `into_inner`, common value traits, and raw `Serialize` /
  `Deserialize` behind the `json` feature. Their Serde representation is the
  complete inner value for transport or storage and is not redacted log output.

### Fixed
- Derives now apply traversal, policy, and formatting bounds to complete field
  types, preserving the actual requirements of wrappers, maps, and policy
  outputs.
- User-defined types named `PhantomData` are traversed normally; only the real
  standard-library marker type receives marker passthrough behavior.
- Policy-formatted `RefCell` fields now emit `<borrowed>` instead of panicking
  when a mutable borrow is active.
- Qualified and dependency-renamed built-in policy paths, plus primitive type
  aliases, now behave like their short-name equivalents without misclassifying
  same-named custom policies.
- Generated derive bindings no longer collide with user fields, variants, or
  generic parameters.
- Generated slog and serialization support now follows the resolved
  `redactable` dependency, so consumers do not need undeclared direct `slog` or
  `serde` dependencies under feature unification.
- `.redacted_json()` now preserves its JSON output contract on serialization
  failure while keeping serializer details and sensitive input out of output.
- The tracing example, feature-isolation CI checks, and affected API
  documentation now match the behavior they exercise.

## 0.10.0

### Added
- `TracingRedactedDebugExt` now provides a plain `tracing` helper for
  structural `Sensitive` values, redacting a clone before recording it as a
  `Debug` field.
- `SensitiveValue<T, P>` and `NotSensitiveValue<T>` now implement `Deserialize`
  behind the `json` feature by deserializing the raw inner value and wrapping it,
  matching their raw `Serialize` behavior.
- Redaction traversal and certification now forward through `VecDeque`, arrays,
  tuples up to four elements, `Mutex`, and `RwLock`. Display formatting also
  supports arrays, tuples up to four elements, `Mutex`, and `RwLock`.

### Changed
- **Breaking:** `RedactedValuable::new` is now crate-private. Construct
  structured tracing values through `.tracing_redacted_valuable()` so callers
  cannot bypass the redaction step with an arbitrary prebuilt value.
- Redacted display formatting for `RefCell` now emits `<borrowed>` when the
  value is already borrowed instead of panicking. `Mutex` and `RwLock` display
  formatting emits `<locked>` when the value cannot be acquired immediately.
- Enum `Debug` output generated by derives now renders compact variant names
  such as `Name::Variant` instead of the token-spaced `Name :: Variant`.

### Fixed
- `SensitiveDisplay` format parsing now accepts `*` and `$` as legal fill
  characters after a fill/alignment pair while continuing to reject true
  dynamic width and precision.
- `SensitiveDisplay` now rejects hex-debug specifiers such as `{field:x?}` and
  `{field:X?}` instead of silently accepting unsupported formatting.
- Generated formatter, mapper, and debug-builder internals no longer collide
  with user fields named `f`, `mapper`, or `debug`.
- Zero-variant enums deriving `Sensitive` or `SensitiveDisplay` now generate
  valid empty-match bodies.
- Container-wrapped IP fields annotated with `#[sensitive(IpAddress)]` now emit
  a targeted compile error explaining the `SensitiveValue<_, IpAddress>`
  workaround.

### Documentation
- Clarified that `#[sensitive(IpAddress)]` applies to bare IP fields only; IP
  values inside containers should use `SensitiveValue<IpAddr, IpAddress>` or
  the corresponding concrete IP wrapper.
- Documented that the `#[sensitive(dual)]` missing-pair compile error does not
  currently fire for generic types.
- Documented the current `{field:?}` template behavior for unannotated
  walk-default fields: it still uses redacted-display semantics rather than
  standard `Debug` quoting.
- Updated the supported-type list for the new standard-library containers.

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

## 0.6.2

### Removed
- `SensitiveDisplay` no longer generates a `RedactableWithMapper` impl. This was added in 0.6.1
  but was a design mistake: newtypes that need structural redaction inside `Sensitive` containers
  should derive `Sensitive` directly. `SensitiveDisplay` is for display/formatting redaction only
  (`RedactableWithFormatter`). The 0.6.1 impl also caused compilation failures for types with
  `Box<dyn Trait>` fields, which are common in error types and one of the primary use cases for
  `SensitiveDisplay`.

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

## 0.5.2 - 2026-02-06

### Documentation
- Improved the decision guide with a three-question derive selection flow,
  common usage patterns, and a trait provision table showing what each derive
  generates.
- Clarified `NotSensitive` migration notes: add `#[derive(Debug)]` explicitly
  when replacing a `Sensitive` derive, and prefer `NotSensitiveDisplay` for
  non-sensitive `Display` types that need logging integration.

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
