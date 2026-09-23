# Redactable reference

This page covers the contracts behind the examples in the [README](../README.md).
Start there for the derive walkthrough and logging examples.

## Contents

- [What each derive generates](#what-each-derive-generates)
- [Low-level traversal](#low-level-traversal)
- [Manual formatters](#manual-formatters)
- [Generic declarations](#generic-declarations)
- [Custom policy formatting](#custom-policy-formatting)
- [Types that implement `Drop`](#types-that-implement-drop)
- [Output and adapter contracts](#output-and-adapter-contracts)
- [Wrapper contracts](#wrapper-contracts)
- [Migrating a local compatibility wrapper](#migrating-a-local-compatibility-wrapper)
- [Supported types](#supported-types)
- [Advanced derive options](#advanced-derive-options)
- [Precedence and edge cases](#precedence-and-edge-cases)
- [Testing redacted output](#testing-redacted-output)
- [Upgrading](#upgrading)

## What each derive generates

| Derive | Use | Requirements for `ToRedacted` | Structured input | `ToRedacted` output | `Debug` |
|---|---|---|---|---|---|
| `Sensitive` | Structured values | `Clone + Serialize` | `Redactable` | Redacted JSON | Redacted |
| `SensitiveDisplay` | Text output | A template | - | Redacted template text | Redacted |
| `SensitiveDual` | Both paths | `Clone + Serialize` and a template | `Redactable` | Redacted template text *and* redacted JSON | Redacted |
| `NotSensitive` | Explicitly non-sensitive structured values | `Serialize` | `Redactable` | Raw JSON, declared public | Not generated |
| `NotSensitiveDisplay` | Explicitly non-sensitive values on both paths | The type's own `Display` | `Redactable` | Raw `Display` text, declared public | Not generated |

The sensitive derives also generate the integrations enabled by `slog` and
`tracing`. Generated `Debug` keeps production redaction in every build.

### Non-sensitive derives

`NotSensitive` generates:

- `RedactableWithMapper`: no-op passthrough (the type has no sensitive data)
- `Redactable`: the derive is an explicit declaration, so the type may be
  redacted and used inside sensitive containers
- `ToRedacted`: emits the raw value as JSON, which is what the declaration
  claims is public (requires `Serialize` on the type)
- `slog::Value` and `SlogRedacted`: serializes the explicitly non-sensitive
  value directly as structured JSON (when `slog` is enabled; requires
  `Serialize` on the type)
- `TracingRedacted`: when `tracing` feature is enabled

`NotSensitiveDisplay` generates:

- `RedactableWithMapper`: no-op passthrough (allows use inside `Sensitive` containers)
- `Redactable`: the derive is an explicit declaration, so the type may be
  redacted and used inside sensitive containers
- `RedactableWithFormatter`: delegates to `Display::fmt` (allows use inside `SensitiveDisplay` containers)
- `ToRedacted`: emits the `Display` text for `slog_redacted()` and `tracing_redacted()`
- `slog::Value` and `SlogRedacted`: when `slog` feature is enabled
- `TracingRedacted`: when `tracing` feature is enabled

## Low-level traversal

Bare leaves do not implement `Redactable`, so calling `.redact()` on a `String`
is a compile error. The free `redact(value)` function uses the lower-level
mapper and can leave a raw leaf unchanged. It is not a logging boundary.
Declarations come from derives, supported manual implementations, and explicit wrappers.
`#[not_sensitive]` skips traversal. Bounds for the selected output still apply.
For example, `Sensitive`'s `ToRedacted` implementation requires `Serialize` on the containing type.

## Manual formatters

A handwritten formatter declares itself by implementing the public
`redactable::DeclaredFormatting` marker trait with `RedactableWithFormatter`.
Constant templates and omitted fields need no formatting declaration.
`SensitiveDual` also checks every structural field, including fields its template omits.

The declaration is an author assertion. It admits the local type as an
unannotated template field. It does not inspect the formatter or validate what
the formatter writes. A declaration also does not admit raw values at a logging
or producer boundary.

```rust
use std::fmt::{Formatter, Result as FmtResult};

use redactable::{DeclaredFormatting, RedactableWithFormatter, SensitiveDisplay};

struct PublicSummary(&'static str);

impl RedactableWithFormatter for PublicSummary {
    fn fmt_redacted(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(self.0)
    }
}

impl DeclaredFormatting for PublicSummary {}

#[derive(SensitiveDisplay)]
#[error("{summary}")]
struct Event {
    summary: PublicSummary,
}

let event = Event { summary: PublicSummary("request accepted") };
assert_eq!(event.redacted_display().to_string(), "request accepted");
```

## Generic declarations

`Sensitive`, `SensitiveDisplay`, and `SensitiveDual` check their required field
operations under the type's declared bounds. Missing capabilities reject the
definition, even when no method or formatting operation is called.

These checks cover field operations. For generic `Sensitive` and `SensitiveDual`
types, the generated `ToRedacted` implementation requires `Clone + Serialize` on
the complete type. Consuming `.redact()` can remain available when those output
bounds are unmet. Concrete types must satisfy these bounds when the derive expands.

Common declaration bounds are:

| Field use | Declaration bound |
|---|---|
| Unannotated structural `value: T` | `T: Redactable` |
| Unannotated referenced template field | Complete field type implements `DeclaredFormatting` |
| `#[sensitive(P)]` with `{value}` | Complete field type implements `PolicyDisplay<P>` |
| `#[sensitive(P)]` with `{value:?}` | Complete field type implements `PolicyDebug<P>` |
| Policy field used in both template forms | Both policy formatting bounds |
| Explicitly public template field | Ordinary `Display`, `Debug`, or both, as used |

`PolicyDisplay<P>` and `PolicyDebug<P>` describe the policy's redacted output.
They do not require the original payload to implement those ordinary formatters.
For a generic policy on a concrete field, use a complete-type bound such as
`u32: PolicyDisplay<P>`. Scalars support `Secret`; bare typed IPs support
`IpAddress`, including `SocketAddr` with its port preserved.

The structural half of `SensitiveDual` also needs each annotated field's
consuming policy operation, expressed by `__private::PolicyField<P>`.
Formatting bounds alone do not supply that operation.

Requirements apply to complete field types. `std::marker::PhantomData<T>` does
not impose redaction on `T`. Map keys remain exempt from value traversal.
`#[redactable(recursive)]` suppresses cyclic inferred predicates; actual field
operations still need to compile under the original declaration.

## Custom policy formatting

The [README custom-policy example](../README.md#custom-policies) defines a
custom `RedactionPolicy`. The [foreign-type example](../README.md#foreign-types)
shows the supported wrapper route: implement `SensitiveWithPolicy<P>` for the
custom value, then carry it as `SensitiveValue<T, P>`.

Use `PolicyFormat` for a custom leaf in a `#[sensitive(P)]` template field.
Its `Output` must implement
`RedactableWithFormatter` for `{value}` or `Debug` for `{value:?}`. Each mode
must render already-redacted data.

```rust
use std::fmt::{Debug, Formatter, Result as FmtResult};

use redactable::{
    PolicyFormat, PolicyFormattingOutput, RedactableMapper, RedactableWithFormatter,
    RedactionPolicy, Secret, SensitiveDisplay,
    policy::RecursivePolicyKind,
};

struct AccountNumber(String);
struct RedactedAccount(String);

impl RedactableWithFormatter for RedactedAccount {
    fn fmt_redacted(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "account({})", self.0)
    }
}

impl Debug for RedactedAccount {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_tuple("RedactedAccount").field(&self.0).finish()
    }
}

impl PolicyFormat for AccountNumber {
    type Output = RedactedAccount;

    fn apply_policy_for_formatting<P, M>(
        &self,
        _mapper: &M,
    ) -> PolicyFormattingOutput<Self::Output>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        PolicyFormattingOutput::Value(RedactedAccount(P::policy().apply_to(&self.0)))
    }
}

#[derive(SensitiveDisplay)]
#[error("{number}")]
struct Transfer {
    #[sensitive(Secret)]
    number: AccountNumber,
}

let transfer = Transfer { number: AccountNumber("12345678".into()) };
let rendered = transfer.redacted_display().to_string();
assert_eq!(rendered, "account([REDACTED])");
assert!(!rendered.contains("12345678"));
```

`PolicyFormat` supports the sealed text and secret recursive policy kinds.
`IpAddressPolicyKind` is not a recursive policy kind. `RedactableMapper` is a
public support trait for the method bound. Its `map_scalar` method has a
`ScalarRedaction` bound. That bound governs scalar mapping inside a mapper. It
does not declare custom values eligible for derive fields, producers, or logging.

Library containers forward to their contents and propagate a nested `RefCell`
borrow conflict as `<borrowed>`. Custom containers must preserve
`PolicyFormattingOutput::Borrowed`. Use `PolicyFormattingOutput::map` to
transform successful output while preserving that state.
`PolicyFormat` does not validate custom output or catch panics.

To migrate an older `fmt_policy_display` or `fmt_policy_debug` override, apply
the policy first and return an owned output newtype. Implement
`RedactableWithFormatter` for `{value}` or `Debug` for `{value:?}`, according to
the modes you support. Keep only the redacted projection in that newtype.
Display and Debug may use different redacted representations.

## Types that implement `Drop`

`Sensitive` and `SensitiveDual` do not support containers that implement `Drop`.
This restriction also applies when every field implements `Copy` and the derive
compiles. Consuming `.redact()` drops the original container; the returned
container is dropped separately. A non-`Copy` field usually causes compilation
to fail with E0509.

The restriction is on the derived container itself. A type that does not
implement `Drop` can still derive `Sensitive` when its fields have their own
drop behavior, provided those fields satisfy the usual traversal bounds.

## Output and adapter contracts

Values that implement `ToRedacted` are called producers. All five derives
provide this implementation. A custom implementation can delegate to
`BypassDisplayRedaction`, `BypassDebugRedaction` or `BypassJsonRedaction`.
Use `BypassDisplayRedaction(text)` for public summary text you compose yourself,
including empty text.
A type with a derive-generated implementation cannot also define a handwritten one.
Use a separate log-view type for a different projection.

Standard containers do not gain `ToRedacted` from their elements. A bare `String`
or `Vec<String>` does not declare logging output. Use a derive, an explicit
public wrapper, or `RedactedList` for a slice of producers.

| Method | Required bounds |
|---|---|
| `.to_redacted()` | `ToRedacted` |
| `.slog_redacted()` | `ToRedacted + Sized` |
| `.slog_redacted_json()` | `ToRedacted` |
| `.tracing_redacted()` | `ToRedacted` |
| `.tracing_redacted_debug()` | `Redactable + Clone + Debug` |
| `.tracing_redacted_valuable()` | `Redactable + Clone + Valuable` |
| `.into_tracing_redacted_debug()` | `Redactable + Debug` |
| `.into_tracing_redacted_valuable()` | `Redactable + Valuable` |

`.to_redacted()`, `.slog_redacted_json()`, and `.tracing_redacted()` also accept
unsized producers, including `&dyn ToRedacted`. `.slog_redacted()` retains its
`Sized` requirement.

### When adapters run

`to_redacted()` borrows its receiver and returns an owned `RedactedValue`.
The result retains no reference to the source and has no public constructor,
`From`, or `Deserialize` implementation.

`.slog_redacted_json()` and `.tracing_redacted()` run the producer at the call.
`.slog_redacted()` holds a reference and runs it each time slog serializes the record.
`.redacted_display()` remains a borrowed formatting view.

### Cloning and borrow conflicts

The producer determines what work happens inside the adapter:

| Producer | Behavior |
|---|---|
| `Sensitive` or `SensitiveDual` | Clone, redact the clone, then serialize it |
| `SensitiveDisplay` | Format the borrowed value through the crate's formatter |
| `NotSensitiveDisplay` | Use the type's own `Display` implementation |
| `NotSensitive` | Serialize the borrowed value |
| `Bypass*` wrappers | Inherit the behavior of the wrapped value |

Structural producers inherit every `Clone` panic. A traversed `RefCell` with a
live mutable borrow therefore panics when the producer runs.
This applies through `.slog_redacted()`, `.slog_redacted_json()`, and `.tracing_redacted()`.

Display producers borrow the source. Generated text/secret formatting needs no
`Clone`; IP-map projections still clone keys and hashers. `SensitiveDisplay`
renders a mutably borrowed `RefCell` as `<borrowed>` through the crate's formatter.
`NotSensitiveDisplay` inherits its own `Display` implementation's borrow behavior.

There is no consuming route to a `RedactedValue`. The consuming
`into_tracing_*` adapters remain for the `Debug` and `Valuable` paths.
They call `.redact()` on the owned value and accept every `Redactable` shape.

Consuming traversal may still clone shared `Arc` or `Rc` referents and map or set hashers.
A live mutable `RefCell` borrow behind shared ownership can therefore still panic.
Prefer `Box` when the logged value has unique ownership.

### Valuable projections

`TracingRedactedValue<T>` owns the redacted object and forwards its borrowed
`Valuable::as_value` and `Valuable::visit` projections. These projections can
expose borrowed inner objects, including `Value::Error`.

`into_inner(self)` consumes the wrapper to return the owned object. Borrowed
projections remain available while the wrapper exists. Caller-driven interior
mutation through an exposed object can affect later projections.
The adapter applies redaction when it is constructed and does not redact each
subsequent projection again.

## Wrapper contracts

Normally choose one policy form: an attribute on a bare field, or an unannotated
`SensitiveValue<T, P>`. If both are combined in a display shape that compiles,
the wrapper's policy is authoritative.

- **`SensitiveValue<T, P>`**
  - Wraps a value of type `T` and associates it with a redaction policy `P`
  - Implements `Debug` with redacted output
  - Does **not** implement `Display` (prevents accidental raw formatting)
  - Implements `ToRedacted`, `slog::Value` + `SlogRedacted` (requires `slog` feature) and `TracingRedacted` (requires `tracing` feature)
  - Provides `.redacted()` for the redacted form and `.expose()` for raw access
- **`BypassRedaction<T>`**
  - Wraps a foreign value to satisfy a `Redactable` bound it cannot implement
  - Passes the value through unchanged
- **`BypassDebugRedaction<T>`**
  - Owns a value explicitly declared safe to log through `Debug`
  - Implements `ToRedacted`, common value traits, `inner()`, and `into_inner()`
- **`BypassDisplayRedaction<T>`**
  - Owns a value explicitly declared safe to log through `Display`
  - Also carries summary text you composed yourself: `BypassDisplayRedaction(text)`
  - Implements `ToRedacted`, common value traits, `inner()`, and `into_inner()`
- **`BypassTextRedaction` (deprecated)**
  - Owns one public `String` and keeps the original `ToRedacted` text and
    `{"message": text}` JSON fallback, including empty text
  - Keeps derived tuple `Debug`, so newlines are escaped and output includes
    `BypassTextRedaction("...")`
  - Does not directly implement `Display`, Serde, slog marker, or tracing
    marker traits; prefer `BypassDisplayRedaction` for new code
- **`BypassJsonRedaction<'_, T>`**
  - Borrows a `Serialize` value and logs it as raw JSON
- **`BypassRedactionMarker<T>`**
  - Declares a value non-sensitive without choosing a logging format
  - Accepted by slog's native typed emitter, which keeps the emitted type instead of flattening it to a string; also accepts a type with neither `Display` nor `Debug`

Every Bypass wrapper is a tuple struct with a public field, so
`BypassJsonRedaction(&value)` or `BypassDisplayRedaction(text)` is the whole
construction. `BypassRedaction<T>` and `BypassRedactionMarker<T>` do not
implement `ToRedacted`: they carry raw application data without choosing a
logging format.

`BypassDisplayRedaction<String>` is a deliberate replacement with a broader
trait set. Migrating to it changes `Debug`: it delegates to the inner
`Display`, so a newline is emitted literally and the tuple name and quotes are
absent. If you deny deprecation warnings, existing uses stop compiling. Check
any `Debug` output your callers rely on when replacing the wrapper.

## Migrating a local compatibility wrapper

If a local wrapper exists only to combine ownership, raw Serde, common traits,
and an explicit output format, replace it with the matching upstream type:

For example, when `public_handler_result` is an application value already reviewed as public:

```rust,ignore
// Before:
// struct NotSensitiveHandlerOutput<T>(T);

// After, when the complete Debug representation is genuinely safe to log:
use redactable::BypassDebugRedaction;

let output = BypassDebugRedaction(public_handler_result);
let raw_result = output.into_inner();
```

Use `BypassDisplayRedaction` instead when `Display` is the approved representation.
This migration is incorrect for outputs that may contain sensitive data; keep a
redaction policy or custom projection for those values.

## Supported types

`#[sensitive(Policy)]` supports `String`, `Cow<'_, str>`, and wrappers such as
`Option<String>`. Borrowed redaction of `Cow<'_, str>` returns an owned
`Cow<'static, str>`. `Sensitive` does not support `&str`; use an owned string or
`Cow`.

`#[sensitive(Secret)]` supports scalars: integers become `0`, floats become
`0.0`, `bool` becomes `false`, and `char` becomes `'*'`. `NonZero*` integers
cannot be policy-annotated because redaction may need to produce zero.

Supported containers are walked automatically. Policy annotations recurse
through options, sequences, arrays, results, maps, and sets. Map keys are not
redacted. Each rendered map key uses its compact or alternate `Debug`
implementation once.

Built-in mapper and formatter support covers:

- scalars, `String`, and `Cow<str>`
- `Option`, `Vec`, `VecDeque`, arrays, tuples up to four elements, `Box`,
  `Arc`, `Rc`, `RefCell`, `Cell`, `Mutex`, `RwLock`, `Result`, maps, and sets
- `Duration`, `Instant`, `SystemTime`, `Ordering`, and `PhantomData`
- `chrono`, `time`, `Uuid`, and IP address types through their corresponding
  features; `extras` enables all four groups

Fields holding `Arc<T>` or `Rc<T>` need serde's `rc` feature in your crate, a
handwritten `Serialize`, or `#[serde(skip)]`, because serde does not serialize
shared pointers by default; this crate does not enable `serde/rc` for you.

Consuming `.redact()` on a poisoned `Mutex` or `RwLock` recovers and redacts
the inner value, then returns a new unpoisoned lock. The result is a logging
projection and does not prove that the original protected value satisfied its
invariants when the lock became poisoned.

The `ip-address` feature supports `IpAddr`, `Ipv4Addr`, `Ipv6Addr`, and
`SocketAddr`. Explicitly public IP fields pass through unchanged.

`#[sensitive(IpAddress)]` accepts a typed IP only as a bare field, including a
bare type alias. Inside containers, wrap each typed value in
`SensitiveValue<_, IpAddress>`. IP policies can recurse through text values.

IP-policy maps preserve their keys and accept only known-safe non-text scalar
key types. Formatting clones allowed keys, and `HashMap` requires a cloneable
hasher. IPv4 output keeps the last octet; IPv6 output keeps the last 16-bit
segment. IPv4-mapped IPv6 uses the IPv4 rule. `SocketAddr` preserves its port.

Under the `redaction` feature, `serde_json::Value` is an opaque traversal leaf.
It redacts to `Value::String("[REDACTED]")` during `.redact()` and adapters that
invoke it, even when unannotated. Generated `Debug` remains annotation-driven.
`redaction` is a default feature and pulls in `serde` and `serde_json`.
The `json` feature remains a compatibility alias for `redaction`; use
`redaction` in new manifests, while existing `json` selections continue to
enable the same capability even with default features disabled.

The API trait implementation lists are authoritative for individual types and
feature gates.

## Advanced derive options

Most types need no `#[redactable(...)]` field option. The derive macros expose
one narrow override for a shape that procedural macros cannot infer on stable
Rust: `recursive` suppresses a cyclic inferred bound on a recursive field. It
applies only to fields.

The former `legacy_formatting` and `generated_formatting` options were removed.
Every `#[sensitive(Policy)]` template field now formats through one borrowed
route, and the derive reports a migration error if either option is still
present. Generated text/secret formatting borrows map keys. A custom leaf used
by `SensitiveDisplay` implements `PolicyFormat`, described
under [Custom policy formatting](#custom-policy-formatting).

Direct generic calls to the legacy `PolicyApplicable` methods require
`P::Kind: RecursivePolicyKind`. Use the kind-aware `apply_policy` and
`apply_policy_ref` free functions when `P` may be an IP policy. The borrowed
free function uses ordinary `RefCell` borrowing and can panic on a conflicting
mutable borrow; generated formatting renders `<borrowed>` instead.

## Precedence and edge cases

**Policy fields:** strings and their containers accept text policies. Scalars
accept only `Secret`. Use `SensitiveValue<T, Policy>` for custom types.

**Empty strings:** built-in strategies return `"[REDACTED]"` for empty input.
A custom full-redaction policy can deliberately choose a different placeholder,
including an empty string.

**Short values:** keep-based policies fully mask values at or below the keep
window. `Email` applies the same rule to its local part.

**Unannotated containers:** traversal still applies annotations found inside a
nested `Sensitive` type.

**Sensitivity attributes are per-field.** Placing `#[sensitive(...)]` or `#[not_sensitive]` on an enum *variant* is a compile error; annotate the variant's fields instead.

**Code-generation helpers are per-field, with no exception.** Container options,
container-level `#[not_sensitive]`, and `#[redactable(...)]` on variants are
rejected, and each rejection names the field placement that would be valid.

**Sets can collapse:** redacted elements are collected back into a set. If
several values become equal, the result shrinks. Use a `Vec` when cardinality
must be preserved.

## Testing redacted output

Enable `testing` alongside the default `redaction` feature to use
`testing::assert_json_shape`. It compares object keys, array lengths and positions,
and scalar JSON kinds.

The helper reads `json()`, so a text-only producer is compared as `{"message": text}`.
Write the expected JSON independently. Check expected policy output and unchanged
public values as well; matching shapes alone cannot prove correct redaction.

Strict JSON Pointer paths can mark opaque nodes. Their parents still require the
node on both sides, and malformed paths are rejected.
Valid paths beneath absent options, empty collections, or scalar parents can remain inactive.
Include populated samples to exercise those paths.

## Upgrading

For the 0.14 upgrade, remove `#[redactable(legacy_formatting)]` and
`#[redactable(generated_formatting)]`. Migrate custom policy-formatting
implementations as described in [Migration from 0.13](../CHANGELOG.md#migration-from-013).
`BypassTextRedaction` is deprecated; check its
[replacement's formatting differences](#wrapper-contracts) before migrating.

In 0.13, generic derives check their required field operations at the type
definition. Add the bounds described in [Generic declarations](#generic-declarations)
before upgrading from 0.12.

`SensitiveDual` replaces the 0.10 combination of `Sensitive`, `SensitiveDisplay`,
and `#[sensitive(dual)]`. The legacy form produces a migration diagnostic.

In 0.12, every structural field and every referenced template field needs a
policy, a declared redacting type, or `#[not_sensitive]`.
Generated `Debug` retains production behavior in consumer tests and with `testing`.
The [0.11 to 0.12 migration table](../CHANGELOG.md#migration-from-011) lists the
removed APIs and their replacements.
