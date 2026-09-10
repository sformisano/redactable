# Redactable

`redactable` marks sensitive fields in Rust structs and enums and produces
redacted output for logging and telemetry. It is not tied to a logging
framework.

Rust examples shown as runnable are compiled by the repository doctest gate. Blocks
marked `ignore` are deliberately incomplete sketches or require an external runtime
such as a configured logger; blocks marked `compile_fail` document rejected usage.

## Table of Contents

- [Getting started](#getting-started)
  - [Quick examples](#quick-examples)
  - [What each derive generates](#what-each-derive-generates)
- [Design principles](#design-principles)
  - [Threat model](#threat-model)
- [How Sensitive works](#how-sensitive-works)
  - [Why do standard leaves implement RedactableWithMapper?](#why-do-standard-leaves-implement-redactablewithmapper)
  - [What if a field doesn't implement RedactableWithMapper?](#what-if-a-field-doesnt-implement-redactablewithmapper)
  - [The `#[sensitive(Policy)]` attribute](#the-sensitivepolicy-attribute)
  - [How the Sensitive macro processes each field](#how-the-sensitive-macro-processes-each-field)
  - [Types that implement `Drop`](#types-that-implement-drop)
- [How SensitiveDisplay works](#how-sensitivedisplay-works)
  - [Template syntax](#template-syntax)
  - [Why do scalars implement RedactableWithFormatter?](#why-do-scalars-implement-redactablewithformatter)
  - [What if a field doesn't implement RedactableWithFormatter?](#what-if-a-field-doesnt-implement-redactablewithformatter)
  - [The `#[sensitive(Policy)]` attribute in templates](#the-sensitivepolicy-attribute-in-templates)
  - [How the SensitiveDisplay macro processes each field](#how-the-sensitivedisplay-macro-processes-each-field)
- [NotSensitive and NotSensitiveDisplay](#notsensitive-and-notsensitivedisplay)
  - [`NotSensitive`](#notsensitive)
  - [`NotSensitiveDisplay`](#notsensitivedisplay)
- [Wrapper types](#wrapper-types)
  - [Choosing a wrapper](#choosing-a-wrapper)
  - [Migrating a local compatibility wrapper](#migrating-a-local-compatibility-wrapper)
  - [Use cases](#use-cases)
- [Integrations](#integrations)
  - [slog](#slog)
  - [tracing](#tracing)
- [Logging safety](#logging-safety)
  - [Enforcing redaction at compile time](#enforcing-redaction-at-compile-time)
  - [`ToRedacted` for custom pipelines](#toredacted-for-custom-pipelines)
- [Reference](#reference)
  - [Supported types](#supported-types)
  - [Advanced derive options](#advanced-derive-options)
  - [Precedence and edge cases](#precedence-and-edge-cases)
  - [Built-in policies](#built-in-policies)
  - [Custom policies](#custom-policies)

## Getting started

There are three derive macros for types with sensitive data. Use `Sensitive` for
structured redaction, `SensitiveDisplay` for formatted redaction, or
`SensitiveDual` when the same type needs both paths.

Use `Sensitive` when you need a **structured redacted value**. `.redact()`
returns the same type with its sensitive fields transformed. The result can be
serialized, logged through the [slog](#slog) and [tracing](#tracing) adapters,
or inspected through `valuable`.

Use `SensitiveDisplay` when you need **formatted redacted text**.
`.redacted_display()` returns a displayable view for errors, flat log lines,
and other text output.

### Quick examples

The runnable structured example uses Serde directly, so declare it alongside
`redactable`. Version 0.12 requires Rust 1.97 or later.

```toml
[dependencies]
redactable = "0.12"
serde = { version = "1", features = ["derive"] }
```

**Structured** (`Sensitive`), with a redacted copy:

```rust
use redactable::{Email, Redactable, Sensitive};

#[derive(Clone, Sensitive, serde::Serialize)]
struct User {
    #[not_sensitive]
    name: String,
    #[sensitive(Email)]
    email: String,
}

let user = User { name: "alice".into(), email: "alice@example.com".into() };
let redacted = user.clone().redact();
assert_eq!(redacted.name, "alice");
assert_eq!(redacted.email, "al***@example.com");

```

**String** (`SensitiveDisplay`), logged as text:

```rust
use redactable::{RedactableWithFormatter, Secret, SensitiveDisplay};

#[derive(SensitiveDisplay)]
enum AuthError {
    #[error("login failed for {user} with {password}")]
    InvalidCredentials {
        #[not_sensitive]
        user: String,
        #[sensitive(Secret)]
        password: String,
    },
}

let err = AuthError::InvalidCredentials {
    user: "alice".into(),
    password: "hunter2".into(),
};
assert_eq!(
    err.redacted_display().to_string(),
    "login failed for alice with [REDACTED]"
);
```

### What each derive generates

Each derive decides what its type produces at a logging boundary: `Sensitive`
redacted JSON, `SensitiveDisplay` redacted text, `SensitiveDual` both, and the
two `NotSensitive` derives the raw value their author declared public.
`ToRedacted` is the trait a logging sink requires; `to_redacted()` returns the
redacted value it sends. [`ToRedacted` for custom
pipelines](#toredacted-for-custom-pipelines) has the details.

| Derive | Use | Requires on the type | Structured input | `ToRedacted` output | `Debug` |
|---|---|---|---|---|---|
| `Sensitive` | Structured values | `Clone + Serialize` | `Redactable` | Redacted JSON | Redacted |
| `SensitiveDisplay` | Text output | A template | - | Redacted template text | Redacted |
| `SensitiveDual` | Both paths | `Clone + Serialize` and a template | `Redactable` | Redacted template text *and* redacted JSON | Redacted |
| `NotSensitive` | Explicitly non-sensitive structured values | `Serialize` | `Redactable` | Raw JSON, declared public | Not generated |
| `NotSensitiveDisplay` | Explicitly non-sensitive values on both paths | The type's own `Display` | `Redactable` | Raw `Display` text, declared public | Not generated |

> **Breaking changes in 0.12:** every structural field, and every field a
> template references, needs a policy, a declared redacting type, or explicit
> `#[not_sensitive]`. Generated `Debug` keeps its production behavior in every
> build, including consumer tests and the `testing` feature. The CHANGELOG
> carries the full 0.11 to 0.12 mapping.

The sensitive derives also generate the logging integrations enabled by the
`slog` and `tracing` features. See [Integrations](#integrations) for their sink
behavior and [Logging safety](#logging-safety) for owned and borrowed adapters.

`SensitiveDual` replaces the 0.10 combination of `Sensitive`,
`SensitiveDisplay`, and `#[sensitive(dual)]`. It generates both paths in one
derive. The legacy form now produces a migration diagnostic.

## Design principles

The library follows three principles:

1. **Field decisions are explicit.** Choose a policy, a declared redacting type
   (a derive, a supported manual implementation, or an explicit wrapper), or an
   explicit public passthrough for each structural or referenced display field.
2. **Traversal is automatic.** Supported containers delegate recursively to
   their contents.
3. **Both output paths use the same annotations.** `#[sensitive(Policy)]`
   applies a policy; `#[not_sensitive]` declares an explicit passthrough.

### Threat model

Redactable protects output only when it passes through a redacted API or a
generated logging integration. Raw field access, direct Serde serialization,
and explicit accessors can still expose the original value. Policies may also
retain approved fragments such as an email domain or token suffix.

Structural derives on containers that implement `Drop` are unsupported.
Borrowed structural adapters that clone the value inherit `Clone` panics.
See [Logging safety](#logging-safety) for the owned and borrowed adapter contracts.

`serde_json::Value` is the main traversal exception. With the default
`redaction` feature, an unannotated value redacts to `"[REDACTED]"` during
`.redact()` and adapters that invoke it. Generated `Debug` remains
annotation-driven.

## How Sensitive works

`Sensitive` implements `RedactableWithMapper`. Containers delegate recursively
until traversal reaches a leaf:

- Unannotated fields must declare `Redactable` behavior, including through
  supported containers.
- Annotated fields (`#[sensitive(Policy)]`) apply the selected policy.
- `#[not_sensitive]` preserves a field unchanged, deliberately bypassing any
  nested policies. Ordinary `Debug` and serialization bounds still apply, so the
  field must satisfy the `Serialize` bound `Sensitive` now places on the container.

| Field kind | What happens |
|---|---|
| **Containers** (structs/enums deriving `Sensitive`) | Traversal walks into them recursively, visiting each field |
| **Ordinary leaves** (`String`, primitives, etc.) | Require a policy or `#[not_sensitive]`; their mapper alone is not a declaration |
| **Supported containers** (`Option`, `Vec`, maps, sets, pointers/cells, etc.) | Delegate recursively to their contained values |
| **Annotated leaves** (`#[sensitive(Policy)]`) | The macro generates transformation code that applies the policy, bypassing the normal passthrough |
| **Explicit passthrough** (`#[not_sensitive]`) | Skips redaction traversal and preserves the field, including foreign values and nested policies |

```rust,compile_fail
use redactable::{Sensitive, Token};

#[derive(Clone, Sensitive, serde::Serialize)]
struct Address {
    #[not_sensitive]
    city: String,
}

#[derive(Clone, Debug, serde::Serialize)]
struct Account {  // Does NOT derive Sensitive
    password: String,
}

#[derive(Clone, Sensitive, serde::Serialize)]
struct User {
    address: Address,       // ✅ container, walks into it
    #[not_sensitive]
    name: String,           // ✅ explicitly public, unchanged
    #[sensitive(Token)]
    api_key: String,        // ✅ annotated leaf, policy applied (redacted)
    account: Account,       // ❌ ERROR: Account does not declare Redactable behavior
}
```

### Why do standard leaves implement RedactableWithMapper?

Standard leaves such as `String` and `u32` implement `RedactableWithMapper`
as a no-op for low-level traversal. Sensitive derives also require `Redactable`
on default fields, so the mapper alone cannot admit an undecided raw leaf.

Bare leaves do not implement `Redactable`, so calling `.redact()` on a `String`
is a compile error. The free `redact(value)` function is lower-level mapper
machinery and can leave a raw leaf unchanged; it is not the logging boundary.
Declarations come from derives, supported manual implementations, and explicit wrappers.

A summary of built-in leaves and containers is in
[Supported types](#supported-types).

```rust
use redactable::{Redactable, Secret, Sensitive};

#[derive(Clone, Sensitive, serde::Serialize)]
struct Inner {
    #[sensitive(Secret)]
    secret: String,
}

#[derive(Clone, Sensitive, serde::Serialize)]
struct Outer {
    #[not_sensitive]
    name: String,                   // explicitly public, unchanged
    #[not_sensitive]
    age: u32,                       // explicitly public, unchanged
    #[not_sensitive]
    maybe_string: Option<String>,   // explicit passthrough of the whole option
    maybe_inner: Option<Inner>,     // Option delegates; Inner is walked and redacted
    #[sensitive(Secret)]
    secret: Option<String>,         // #[sensitive(Secret)] applies through the Option
}

let outer = Outer {
    name: "alice".into(),
    age: 30,
    maybe_string: Some("visible".into()),
    maybe_inner: Some(Inner { secret: "hidden".into() }),
    secret: Some("also_hidden".into()),
};
let redacted = outer.redact();

assert_eq!(redacted.name, "alice");                               // unchanged
assert_eq!(redacted.age, 30);                                     // unchanged
assert_eq!(redacted.maybe_string, Some("visible".into()));        // unchanged
assert_eq!(redacted.maybe_inner.unwrap().secret, "[REDACTED]");   // walked and redacted
assert_eq!(redacted.secret, Some("[REDACTED]".into()));           // policy applied
```

### What if a field doesn't implement RedactableWithMapper?

If a default field lacks declared `Redactable` behavior, you get a compilation
error. A raw leaf needs a policy or explicit `#[not_sensitive]`. For other types:

- **Local types:** derive `Sensitive` on the type so it participates in traversal:

  ```rust
  use redactable::Sensitive;

  #[derive(Clone, Sensitive, serde::Serialize)]
  struct Account { /* ... */ }  // now implements RedactableWithMapper
  ```

- **Foreign types**: use `#[not_sensitive]` to skip the field. This sketch uses
  a placeholder external crate and is intentionally incomplete:

  ```rust,ignore
  use external_crate::Timeout;

  #[derive(Clone, Sensitive, serde::Serialize)]
  struct Config {
      #[not_sensitive]
      timeout: Timeout,  // skips RedactableWithMapper entirely
  }
  ```

  `#[not_sensitive]` is the declaration for a non-sensitive foreign field. When the foreign value is sensitive, [Wrapper types for foreign types](#foreign-types) shows the `SensitiveValue<T, P>` route.

### The `#[sensitive(Policy)]` attribute

`#[sensitive(Policy)]` marks a leaf as sensitive. The derive applies the policy
instead of the normal `RedactableWithMapper` passthrough:

- `#[sensitive(Secret)]` on scalars: replaces the value with a default (0, false, `'*'`)
- `#[sensitive(Secret)]` on strings: replaces with `"[REDACTED]"`
- `#[sensitive(Policy)]` on strings: applies the policy's redaction rules

```rust
use redactable::{Email, Secret, Sensitive};

#[derive(Clone, Sensitive, serde::Serialize)]
struct Login {
    #[not_sensitive]
    username: String,           // explicitly public, unchanged
    #[sensitive(Secret)]
    password: String,           // redacted to "[REDACTED]"
    #[sensitive(Email)]
    email: String,              // redacted to "al***@example.com"
    #[sensitive(Secret)]
    attempts: u32,              // redacted to 0
}
```

`#[sensitive(Secret)]` accepts both bare primitive names such as `u32` and qualified standard-library paths such as `std::primitive::u32`.

### How the Sensitive macro processes each field

```mermaid
flowchart TD
    F["For each field"] --> A{"Annotated with<br/>#[sensitive(Policy)]?"}
    A -- Yes --> T{"Field type?"}
    T -- "String-like<br/>(String, Cow, Option&lt;String&gt;, etc.)" --> B["Apply text redaction policy<br/>e.g. Email becomes al***@example.com"]
    T -- "Scalar<br/>(only #[sensitive(Secret)])" --> C["Replace with default<br/>u32 becomes 0, bool becomes false"]
    T -- "Typed IP address<br/>(only #[sensitive(IpAddress)])" --> C2["Apply the IP policy<br/>keeps the last IPv4 octet or IPv6 segment"]
    A -- No --> D{"Annotated with<br/>#[not_sensitive]?"}
    D -- Yes --> E["Preserve field<br/>ordinary output bounds still apply"]
    D -- No --> G{"Declares<br/>Redactable?"}
    G -- "Yes, derived type" --> I["Use declared traversal"]
    G -- "Yes, supported container<br/>with declared contents" --> I
    G -- No --> K["Compile error"]
```

### Types that implement `Drop`

`Sensitive` consumes `self` and moves its fields into a redacted value of the
same type. Container types that implement `Drop` are unsupported, including
Copy-only shapes that happen to compile: `.redact()` drops the consumed original
and later drops the replacement, which is not a supported container lifecycle.
This limitation also applies to `SensitiveDual`. A non-`Copy` field usually
makes the unsupported shape fail earlier with E0509.

The restriction is on the derived container itself. A type that does not
implement `Drop` can still derive `Sensitive` when its fields have their own
drop behavior, provided those fields satisfy the usual traversal bounds.

## How SensitiveDisplay works

`SensitiveDisplay` implements `RedactableWithFormatter`. It is template-driven:
only fields referenced in the display template are formatted. `Sensitive`
instead walks every field and produces a redacted value of the same type.

It formats by reference and produces a string. The generated text/secret route
does not require `Clone`; individual policy projections can add documented
bounds (IP-policy maps currently clone allowed keys and hashers):

- Unannotated fields in the template must declare redacted formatting behavior.
- Annotated fields (`#[sensitive(Policy)]`) have redaction applied before formatting.
- Fields not in the template are not formatted at all.

| Field kind | What happens |
|---|---|
| **Nested types** (structs/enums deriving `SensitiveDisplay`) | Uses their `RedactableWithFormatter` to produce a redacted substring |
| **Raw scalars and containers of raw scalars** | Require a policy or explicit `#[not_sensitive]` when referenced |
| **Annotated fields** (`#[sensitive(Policy)]`) | The macro generates formatting code that applies the policy |
| **Explicit passthrough** (`#[not_sensitive]`) | Renders via raw `Display` (or `Debug` if `{:?}`). Skips the `RedactableWithFormatter` requirement. Use for types without a built-in implementation |

```rust,compile_fail
use redactable::{RedactableWithFormatter, Secret, SensitiveDisplay};
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(SensitiveDisplay)]
enum InnerError {
    #[error("db password {password}")]
    Database {
        #[sensitive(Secret)]
        password: String,
    },
}

struct ExternalContext;  // Does NOT derive SensitiveDisplay
impl Display for ExternalContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("external")
    }
}

#[derive(SensitiveDisplay)]
enum AppError {
    #[error("user {name} (attempt {count})")]
    UserError {
        #[not_sensitive]
        name: String,              // ✅ explicitly public text
        #[not_sensitive]
        count: u32,                // ✅ explicitly public count
    },

    #[error("auth: {password}")]
    AuthFailed {
        #[sensitive(Secret)]
        password: String,          // ✅ annotated, becomes "[REDACTED]"
    },

    #[error("caused by: {source}")]
    Nested {
        source: InnerError,        // ✅ nested type, redacted via RedactableWithFormatter
    },

    #[error("context: {ctx}")]
    WithContext {
        ctx: ExternalContext,      // ❌ ERROR: missing declared redacted formatting
    },
}

let err = AppError::UserError { name: "alice".into(), count: 3 };
assert_eq!(err.redacted_display().to_string(), "user alice (attempt 3)"); // scalars unchanged

let err = AppError::AuthFailed { password: "hunter2".into() };
assert_eq!(err.redacted_display().to_string(), "auth: [REDACTED]"); // policy applied

let err = AppError::Nested {
    source: InnerError::Database { password: "secret".into() },
};
assert_eq!(
    err.redacted_display().to_string(),
    "caused by: db password [REDACTED]"
); // nested redaction
```

### Template syntax

The display template comes from one of two sources:

**`#[error("...")]` attribute** (thiserror-style):

```rust
use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
enum ApiError {
    #[error("auth failed for {user}")]
    AuthFailed { #[not_sensitive] user: String },
}
```

**Doc comment** (same syntax as `displaydoc`, but parsed by the macro itself):

```rust
use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
enum ApiError {
    /// auth failed for {user}
    AuthFailed { #[not_sensitive] user: String },
}
```

Both support named placeholders (`{field_name}`), positional placeholders (`{0}`, `{1}`), and debug formatting (`{field:?}`).

`{field:?}` on a declared unannotated field uses redacted-display semantics.
An explicitly public field uses ordinary `Debug`, including string quotes and
escaping. Migrating a former raw `String` to `#[not_sensitive]` therefore adds
quotes with `:?`; choose `{field}` when plain public text is intended.

Positional placeholders must be contiguous from `0`; `{1}` without `{0}` is
rejected. Dynamic width or precision, such as `{value:.*}`, and non-Display or
Debug specifiers, such as `{value:x}`, are also rejected.

### Why do scalars implement RedactableWithFormatter?

Standard scalars such as `String` and `u32` provide the low-level formatting
machinery, but a template that references a field also requires that field's
type to declare redacted formatting. Raw leaves need a policy or explicit
`#[not_sensitive]`; supported containers pass the requirement on to their
contents.

Constant templates and omitted fields need no declaration. `SensitiveDual`
additionally checks every field for structural traversal, including fields its
template omits. A handwritten formatter declares itself by implementing the
hidden `redactable::__private::DeclaredFormatting` marker trait.

```rust
use redactable::{RedactableWithFormatter, SensitiveDisplay};

#[derive(SensitiveDisplay)]
enum Event {
    #[error("user {name} (age {age}, active: {active})")]
    UserInfo {
        #[not_sensitive]
        name: String,       // formats as "alice"
        #[not_sensitive]
        age: u32,           // formats as "30"
        #[not_sensitive]
        active: bool,       // formats as "true"
    },
}

let event = Event::UserInfo { name: "alice".into(), age: 30, active: true };
assert_eq!(
    event.redacted_display().to_string(),
    "user alice (age 30, active: true)"
);
```

### What if a field doesn't implement RedactableWithFormatter?

If a template references a default field without declared redacted formatting,
you get a compilation error. For raw leaves, choose a policy or explicit
`#[not_sensitive]`. For other types:

- **Local types:** derive `SensitiveDisplay` on the type so it participates in redacted formatting:

  ```rust
  use redactable::SensitiveDisplay;

  #[derive(SensitiveDisplay)]
  enum DatabaseError {
      #[error("connection failed: {detail}")]
      Connection { #[not_sensitive] detail: String },
  }
  // Now DatabaseError implements RedactableWithFormatter
  ```

- **Foreign types:** use `#[not_sensitive]` to render via raw `Display` instead.
  This sketch uses a placeholder external crate and is intentionally incomplete:

  ```rust,ignore
  use external_crate::ErrorContext;

  #[derive(SensitiveDisplay)]
  enum AppError {
      #[error("context: {ctx}")]
      WithContext {
          #[not_sensitive]
          ctx: ErrorContext,  // renders via Display, skips RedactableWithFormatter
      },
  }
  ```

  `#[not_sensitive]` is the declaration for a non-sensitive foreign field. See [Wrapper types for foreign types](#foreign-types) for the sensitive case.

### The `#[sensitive(Policy)]` attribute in templates

`#[sensitive(Policy)]` has the same policy behavior as `Sensitive`, but formats
the result into the template:

- `#[sensitive(Secret)]` on strings: replaces with `"[REDACTED]"`
- `#[sensitive(Secret)]` on scalars: replaces with the default value (`0`, `false`, `'*'`)
- `#[sensitive(Policy)]` on strings: applies the policy's redaction rules
- `#[sensitive(Policy)]` on containers such as `Option<String>` or `Vec<String>`: applies the policy to each contained string, then formats the redacted container in the template

```rust
use redactable::{Email, RedactableWithFormatter, Secret, SensitiveDisplay, Token};

#[derive(SensitiveDisplay)]
enum AuthEvent {
    #[error("login by {email} with token {token} (attempt {attempt})")]
    Login {
        #[sensitive(Email)]
        email: String,              // becomes "al***@example.com"
        #[sensitive(Token)]
        token: String,              // becomes "***********2345"
        #[sensitive(Secret)]
        attempt: u32,               // becomes 0
    },
}

let event = AuthEvent::Login {
    email: "alice@example.com".into(),
    token: "sk-secret-12345".into(),
    attempt: 3,
};
assert_eq!(
    event.redacted_display().to_string(),
    "login by al***@example.com with token ***********2345 (attempt 0)"
);
```

### How the SensitiveDisplay macro processes each field

```mermaid
flowchart TD
    F["For each field<br/>in the template"] --> A{"Annotated with<br/>#[sensitive(Policy)]?"}
    A -- Yes --> T{"Field type?"}
    T -- "String-like<br/>(String, Cow, Option&lt;String&gt;, etc.)" --> B["Format with redaction policy<br/>e.g. Email becomes al***@example.com"]
    T -- "Scalar<br/>(only #[sensitive(Secret)])" --> C["Format default value<br/>u32 becomes 0, bool becomes false"]
    A -- No --> D{"Annotated with<br/>#[not_sensitive]?"}
    D -- Yes --> E["Use ordinary Display or Debug<br/>requires that formatting trait"]
    D -- No --> G{"Declares<br/>redacted formatting?"}
    G -- Yes --> I["Format via fmt_redacted<br/>(redacted substring)"]
    G -- No --> K["Compile error"]
```

## NotSensitive and NotSensitiveDisplay

Types with no sensitive data still need to participate in the redaction system for two reasons:

1. **Composition**: non-sensitive field types still need to satisfy the
   structured or formatted traversal bound of their container.

2. **Logging safety**: non-sensitive types need explicit certification to pass
   the same logging bounds as sensitive values.

`NotSensitive` certifies the structured path. `NotSensitiveDisplay` certifies
both the structured and formatted paths. Both generate no-op traversal, a
`ToRedacted` output that publishes the value as its author declared, and the
enabled logging integrations, including the `SlogRedacted` and
`TracingRedacted` marker traits described under
[Logging safety](#logging-safety).

These are derives for types you own; see [Wrapper types](#wrapper-types) for
foreign values.

### `NotSensitive`

`NotSensitive` is for types with no sensitive data that need to work inside `Sensitive` containers:

```rust
use redactable::{NotSensitive, Secret, Sensitive};

#[derive(Clone, Debug, NotSensitive, serde::Serialize)]
struct PublicMetadata {
    version: String,
    timestamp: u64,
}

#[derive(Clone, Sensitive, serde::Serialize)]
struct Config {
    #[sensitive(Secret)]
    api_key: String,
    metadata: PublicMetadata,  // ✅ NotSensitive provides RedactableWithMapper
}
```

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

### `NotSensitiveDisplay`

`NotSensitiveDisplay` is for types with no sensitive data that have a `Display` impl:

```rust
use std::fmt::{Display, Formatter, Result as FmtResult};
use redactable::NotSensitiveDisplay;

/// Retry using backoff
#[derive(Clone, NotSensitiveDisplay)]
enum RetryDecision {
    Retry { delay_ms: u64 },
    Abort,
}

impl Display for RetryDecision {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Retry { delay_ms } => write!(f, "Retry after {}ms", delay_ms),
            Self::Abort => write!(f, "Abort"),
        }
    }
}
```

`NotSensitiveDisplay` generates:
- `RedactableWithMapper`: no-op passthrough (allows use inside `Sensitive` containers)
- `Redactable`: the derive is an explicit declaration, so the type may be
  redacted and used inside sensitive containers
- `RedactableWithFormatter`: delegates to `Display::fmt` (allows use inside `SensitiveDisplay` containers)
- `ToRedacted`: emits the `Display` text, certifying the type for `slog_redacted()` and `tracing_redacted()`
- `slog::Value` and `SlogRedacted`: when `slog` feature is enabled
- `TracingRedacted`: when `tracing` feature is enabled

This cross-path compatibility lets `NotSensitiveDisplay` work as a field in
both `Sensitive` and `SensitiveDisplay` containers. `SensitiveDual` is the
sensitive cross-path derive when both behaviors are required.

`NotSensitiveDisplay` works naturally with `displaydoc` or similar crates that derive `Display`:

This optional example requires a direct `displaydoc` dependency and is
intentionally not part of the standalone doctest set:

```rust,ignore
use redactable::NotSensitiveDisplay;

#[derive(Clone, displaydoc::Display, NotSensitiveDisplay)]
enum RetryDecision {
    /// Retry using backoff
    Retry,
    /// Do not retry
    Abort,
}
// Now RetryDecision has Display (from displaydoc), RedactableWithFormatter, slog::Value, etc.
```

## Wrapper types

The library provides one policy-bearing wrapper and a family of explicit
escapes, each named for the redaction it bypasses. `SensitiveValue<T, P>`
carries a policy in the type and is a normal field type. The Bypass wrappers
are for values you do not own, or for an API that bounds the value itself
rather than a field of yours; a non-sensitive foreign field of a type you own
takes `#[not_sensitive]` instead.

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
  - Implements `ToRedacted`, common value traits, `inner()`, and `into_inner()`
- **`BypassJsonRedaction<'_, T>`**
  - Borrows a `Serialize` value and logs it as raw JSON
- **`BypassTextRedaction(String)`**
  - Carries summary text you composed yourself
- **`BypassRedactionMarker<T>`**
  - Declares a value non-sensitive without choosing a logging format
  - Accepted by slog's native typed emitter, which keeps the emitted type instead of flattening it to a string; also accepts a type with neither `Display` nor `Debug`

Every Bypass wrapper is a tuple struct with a public field, so
`BypassJsonRedaction(&value)` or `BypassTextRedaction(text)` is the whole
construction. `BypassRedaction<T>` and `BypassRedactionMarker<T>` do not
implement `ToRedacted`: they carry raw application data without choosing a
logging format.

### Choosing a wrapper

Treat explicitly non-sensitive wrappers as exceptional declarations. Most
application output can contain sensitive data and should use a policy or a
purpose-built redacted projection.

| Need | Use |
|---|---|
| Sensitive leaf with a policy | `SensitiveValue<T, P>` |
| Sensitive structured output | `Sensitive` or `SensitiveDual`; the derive produces the JSON |
| Restricted summary or selected shape | A log-view type deriving the shape you want, or `BypassTextRedaction` for author-composed text |
| Genuinely public value logged with `Debug` | `BypassDebugRedaction<T>` |
| Genuinely public value logged with `Display` | `BypassDisplayRedaction<T>` |
| Borrowed value logged as raw JSON | `BypassJsonRedaction<'_, T>` |
| Foreign value at a `Redactable`-bounded boundary | `BypassRedaction<T>` |
| Value with neither `Display` nor `Debug` | `BypassRedactionMarker<T>` |

A customer record, token, or handler result that may contain private fields
needs redaction before logging. Use `SensitiveValue<T, P>` for a leaf policy,
or a sensitive derive for structured output.

⚠️ `BypassDebugRedaction<T>`, `BypassDisplayRedaction<T>` and
`BypassRedaction<T>` serialize and deserialize exactly like `T`. That raw Serde
representation is for normal transport or storage, may expose the entire value,
and is not sanitized logging output.

Sensitive wrappers follow the same rule: transport keeps the raw value, while
the logging boundary applies its policy. This example also needs
`serde_json = "1"` as a direct dependency.

```rust
use redactable::{Secret, SensitiveValue, ToRedacted};

let token = SensitiveValue::<String, Secret>::from("secret".to_owned());
assert_eq!(serde_json::to_value(&token).unwrap(), serde_json::json!("secret"));
assert_eq!(token.to_redacted().text(), "[REDACTED]");
```

### Migrating a local compatibility wrapper

If a local wrapper exists only to combine ownership, raw Serde, common traits,
and an explicit output format, replace it with the matching upstream type:

The following is a migration sketch with application-specific values omitted:

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

### Use cases

Wrapper types exist for two purposes:

#### Foreign types

Types from other crates cannot use your derives, and the orphan rule prevents
you from implementing redactable's traversal traits for them. Wrappers provide
those implementations. A local policy type can implement
`SensitiveWithPolicy<P>` for the foreign value.

For a sensitive foreign type, define a [local policy](#custom-policies),
implement `SensitiveWithPolicy<P>`, and use `SensitiveValue`:

```rust
use redactable::{
    RedactionPolicy, Sensitive, SensitiveValue, SensitiveWithPolicy, TextPolicyKind,
    TextRedactionPolicy,
};

// Imagine this comes from a payments SDK.
// It exposes accessors but no redaction support.
#[derive(Clone, Debug, serde::Serialize)]
struct MerchantAccount {
    id: String,
    name: String,
    tax_id: String,
}

impl MerchantAccount {
    fn tax_id(&self) -> &str { &self.tax_id }
}

// The policy type must be local to your crate: that is what satisfies the
// orphan rule for the SensitiveWithPolicy impl on the foreign type.
#[derive(Clone, Copy)]
struct MerchantPii;

impl RedactionPolicy for MerchantPii {
    type Kind = TextPolicyKind;

    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(2)
    }
}

impl SensitiveWithPolicy<MerchantPii> for MerchantAccount {
    fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self {
        Self {
            id: self.id,
            name: policy.apply_to(&self.name),
            tax_id: policy.apply_to(&self.tax_id),
        }
    }
    fn redacted_string(&self, policy: &TextRedactionPolicy) -> String {
        format!("MerchantAccount({}, {})", policy.apply_to(&self.name), policy.apply_to(&self.tax_id))
    }
}

#[derive(Clone, Sensitive, serde::Serialize)]
struct PaymentConfig {
    merchant: SensitiveValue<MerchantAccount, MerchantPii>,
}
```

The example below shows both halves of the rule: a non-sensitive foreign field
declared with `#[not_sensitive]`, and `BypassRedaction<T>` at an API that
demands `Redactable` on the foreign value itself.

```rust
use redactable::{BypassRedaction, Redactable, Sensitive};

#[derive(Clone, Debug, serde::Serialize)]
struct ForeignConfig { timeout: u64 }  // (pretend this is from another crate)

#[derive(Clone, Sensitive, serde::Serialize)]
struct AppConfig {
    #[not_sensitive]
    foreign: ForeignConfig,  // passes through unchanged
}

// A boundary that bounds the value itself, not a field of yours:
fn store<T: Redactable>(value: T) -> T { value.redact() }

let kept = store(BypassRedaction(ForeignConfig { timeout: 30 }));
assert_eq!(kept.0.timeout, 30);
```

#### Field-level redaction awareness

With `#[sensitive(P)]`, a field keeps its original runtime type and can still be
accessed or formatted without redaction. `SensitiveValue<T, P>` carries the
policy in the runtime type, provides redacted `Debug`, and deliberately omits
`Display`.

Normally choose exactly one policy form: annotate a bare field with
`#[sensitive(P)]`, or use an unannotated `SensitiveValue<T, P>`. If a direct
annotation is combined with a wrapper in a display shape that compiles, the
wrapper's own policy is authoritative.

This logging sketch omits the surrounding application logger configuration:

```rust,ignore
#[derive(Clone, Sensitive, serde::Serialize)]
struct User {
    email: SensitiveValue<String, Pii>,  // The value IS a wrapper, not a bare String
}

let user = User { email: SensitiveValue::from(String::from("alice@example.com")) };

// ✅ Safe: Debug shows the policy-redacted value, not the raw email
log::info!("Email: {:?}", user.email);

// ✅ Safe: explicit call for redacted form
log::info!("Email: {}", user.email.redacted());

// ⚠️ Intentional: .expose() for raw access (code review catches this)
let raw = user.email.expose();
```

Compare with `#[sensitive(P)]` attributes, where the field is a bare type at runtime:

| | `#[sensitive(P)]` | `SensitiveValue<T, P>` |
|---|---|---|
| **Ergonomics** | ✅ Work with actual types | ❌ Need `.expose()` everywhere |
| **Display (`{}`)** | Shows raw value | ✅ Not implemented (won't compile) |
| **Debug (`{:?}`)** | Shows raw value | ✅ Shows policy-redacted value |
| **Serialization** | Shows raw value | Shows raw value |
| **slog/tracing safety** | ✅ Via container | ✅ Direct |

The attribute affects output generated for the containing type, not direct
formatting of the field. `Sensitive`'s generated `Debug` uses the generic
`[REDACTED]` placeholder. `SensitiveDisplay` and the display-selected `Debug`
generated by `SensitiveDual` use the declared template, so policy annotations
may preserve shaped fragments such as an email domain or token suffix.

Both forms serialize raw values. Use `.redact()` or `.to_redacted()` when the
serialized boundary must be redacted.
`SensitiveValue` is a leaf wrapper and does not walk nested field annotations.
Local structured types should derive `Sensitive` instead.

## Integrations

### slog

The `slog` feature makes derived types and `SensitiveValue` implement
`slog::Value`, so you can pass them to slog directly:

```toml
[dependencies]
redactable = { version = "0.12", features = ["slog"] }
serde = { version = "1", features = ["derive"] }
slog = "2.8"
```

Structured slog output relies on nested-value support throughout the drain
stack. When using drains such as `slog-async` or `slog-json`, enable each
drain crate's `nested-values` feature as well. Enabling `redactable/slog`
enables the feature on `slog` itself, but not on separate drain crates.

**Containers**: the `Sensitive` derive generates `slog::Value` automatically:

```rust
use redactable::{CreditCard, Email, Sensitive};
use serde::Serialize;
use slog::{Discard, Logger};

#[derive(Clone, Sensitive, Serialize)]
struct PaymentEvent {
    #[sensitive(Email)]
    customer_email: String,
    #[sensitive(CreditCard)]
    card_number: String,
    #[not_sensitive]
    amount: u64,
}

let event = PaymentEvent {
    customer_email: "alice@example.com".into(),
    card_number: "4111111111111234".into(),
    amount: 9999,
};

// Just log it - slog::Value impl handles redaction automatically
let logger = Logger::root(Discard, slog::o!());
slog::info!(logger, "payment"; "event" => &event);
// Borrowed generated output: "[REDACTED]"
```

**Leaf wrappers**: `SensitiveValue<T, P>` also implements `slog::Value`:

```rust
use redactable::{SensitiveValue, Token};
use slog::{Discard, Logger};

let api_token: SensitiveValue<String, Token> = SensitiveValue::from(String::from("sk-secret-key"));

// Also automatic - SensitiveValue has its own slog::Value impl
let logger = Logger::root(Discard, slog::o!());
slog::info!(logger, "auth"; "token" => &api_token);
// Logged: "*********-key"
```

Both work because they implement `slog::Value`. Containers get it via the
derive macro, wrappers via a manual implementation. What slog receives depends
on the derive. A borrowed `Sensitive` or `SensitiveDual` value fails closed to
`"[REDACTED]"`; `.slog_redacted_json()` is the call that clones, redacts and
emits its JSON. `SensitiveDisplay` emits its redacted text, `NotSensitive` its
raw JSON, and `NotSensitiveDisplay` its raw `Display` text.

### tracing

For structural values with any tracing subscriber, use the plain `tracing`
feature and log the redacted `Debug` form:

```toml
[dependencies]
redactable = { version = "0.12", features = ["tracing"] }
serde = { version = "1", features = ["derive"] }
tracing = "0.1"
```

The tracing integration tests check the `AuthEvent` example below and the
Valuable and display adapters.

```rust,ignore
use redactable::{Email, Sensitive, Token};
use redactable::tracing::TracingRedactedDebugExt;

#[derive(Clone, Sensitive, serde::Serialize)]
struct AuthEvent {
    #[sensitive(Token)]
    api_key: String,
    #[sensitive(Email)]
    user_email: String,
    #[not_sensitive]
    action: String,
}

let event = AuthEvent {
    api_key: "sk-secret-key-12345".into(),
    user_email: "alice@example.com".into(),
    action: "login".into(),
};

// Redacts a clone before the value reaches the tracing subscriber.
tracing::info!(event = event.tracing_redacted_debug());
// Production output: AuthEvent { api_key: "[REDACTED]", user_email: "[REDACTED]", action: "login" }
```

That exact line is also the output in consumer tests and with the `testing`
feature. Generated `Debug` keeps full suppression for these policy fields.

For typed structured logging, use the `valuable` integration. Upstream tracing
requires `RUSTFLAGS="--cfg tracing_unstable"` for `tracing::field::valuable`,
and the field expression must pass a reference through that adapter:

```toml
[dependencies]
redactable = { version = "0.12", features = ["tracing-valuable"] }
serde = { version = "1", features = ["derive"] }
tracing = "0.1"
valuable = { version = "0.1", features = ["derive"] }
```

This example requires `RUSTFLAGS="--cfg tracing_unstable"`, which the CI gate
sets for its consumer fixtures:

```rust,ignore
use redactable::{Email, Sensitive, Token};
use redactable::tracing::TracingValuableExt;

#[derive(Clone, Sensitive, serde::Serialize, valuable::Valuable)]
struct AuthEvent {
    #[sensitive(Token)]
    api_key: String,
    #[sensitive(Email)]
    user_email: String,
    #[not_sensitive]
    action: String,
}

let event = AuthEvent {
    api_key: "sk-secret-key-12345".into(),
    user_email: "alice@example.com".into(),
    action: "login".into(),
};

let redacted = event.tracing_redacted_valuable();
tracing::info!(event = tracing::field::valuable(&redacted));
// Logged: {api_key: "***************2345", user_email: "al***@example.com", action: "login"}
```

Unlike slog where `slog::Value` can be implemented automatically via the derive
macro, tracing's `Value` trait is sealed. The `valuable` crate provides the
structured data path, but `TracingRedactedValue<T>` is not itself a tracing field
value. `.tracing_redacted_valuable()` redacts first; `tracing::field::valuable`
adapts the binding for subscribers that support `valuable`.

**For flat display values** (without `valuable`):

```rust,ignore
use redactable::{Email, SensitiveValue, Token};
use redactable::tracing::TracingRedactedExt;

let api_key: SensitiveValue<String, Token> = SensitiveValue::from(String::from("sk-secret-key-12345"));
let user_email: SensitiveValue<String, Email> = SensitiveValue::from(String::from("alice@example.com"));

tracing::info!(
    api_key = api_key.tracing_redacted(),
    user_email = user_email.tracing_redacted(),
    action = "login"
);
// Logged: api_key="***************2345" user_email="al***@example.com" action="login"
```

The display path also works for `SensitiveDisplay`, `SensitiveDual`,
`NotSensitiveDisplay`, and other values that implement `ToRedacted`.

## Logging safety

The [slog](#slog) and [tracing](#tracing) integrations handle the common sink
paths. Marker traits and `ToRedacted` enforce the same boundary in custom
logging code.

### Enforcing redaction at compile time

`SlogRedacted` and `TracingRedacted` are marker traits for values with
logging-safe sink integrations. All five derive macros implement them
automatically when the corresponding feature is enabled, as does
`SensitiveValue<T, P>`. Wrapping a value in `BypassRedactionMarker` is an
explicit declaration that certifies the wrapper for `TracingRedacted` and, when
the wrapped value or reference implements `slog::Value`, for `SlogRedacted`; the
raw value, including a raw `String`, remains uncertified. A bound is only half
of the contract: your macro must also call the redacting adapter or pass the
explicitly certified wrapper instead of passing raw values to the sink.

For slog, use `SlogRedacted` with `slog::Value` and pass the value to slog's
field API:

This macro sketch includes application values and a deliberately rejected raw
field call, which the slog suites check with separate fixtures:

```rust,ignore
use redactable::slog::SlogRedacted;

macro_rules! slog_safe {
    ($logger:expr, $msg:literal; $($key:literal => $value:expr),* $(,)?) => {{
        fn assert_slog_safe<T: SlogRedacted + slog::Value>(_: &T) {}
        $(assert_slog_safe(&$value);)*
        slog::info!($logger, $msg; $($key => &$value),*);
    }};
}

// ✅ Works: Sensitive-derived types implement SlogRedacted
slog_safe!(logger, "user logged in"; "user" => &user);

// ✅ Works: SensitiveValue implements SlogRedacted
slog_safe!(logger, "auth"; "token" => &api_token);  // SensitiveValue<String, Token>

// ❌ Won't compile: raw String doesn't implement SlogRedacted
slog_safe!(logger, "user"; "email" => &user.email);
```

For structural tracing fields, use the extension trait as the compile-time
gate:

This macro sketch uses the structural tracing adapter, which the integration
suite checks through a captured tracing event:

```rust,ignore
use redactable::tracing::TracingRedactedDebugExt;

macro_rules! trace_safe {
    ($($key:ident = $value:expr),* $(,)?) => {{
        fn assert_tracing_safe<T: TracingRedactedDebugExt>(_: &T) {}
        $(assert_tracing_safe(&$value);)*
        tracing::info!($($key = $value.tracing_redacted_debug()),*);
    }};
}
```

### `ToRedacted` for custom pipelines

For custom logging, require `ToRedacted`. Its one method, `to_redacted()`,
returns a `RedactedValue` carrying redacted text, redacted JSON, or both, as
decided by the derive that produced it. `text()` returns the text, or the JSON
as compact text; `json()` returns the JSON, or the text as `{"message": …}`.
Both always return a value. The value is computed when it is produced, and a
`RedactedValue` only comes from a producer: there is no constructor, no `From`,
and no `Deserialize`.

The trait is open. Implement it for your own type by delegating to an explicit
escape: `BypassDisplayRedaction`, `BypassDebugRedaction`, `BypassJsonRedaction`,
or `BypassTextRedaction(String)` for summary text you compose, including empty
text. A type that derives `Sensitive`, `SensitiveDual`, `SensitiveDisplay`,
`NotSensitive`, or `NotSensitiveDisplay` already implements `ToRedacted`; a
second implementation on the same type will not compile, so a different
projection belongs on its own log-view type.

Standard containers do not gain output certification from their elements. A
bare `String` or `Vec<String>` cannot be certified as redacted output.

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

`to_redacted()` borrows its receiver and returns an owned value. What happens
inside depends on the producer. The structural producers generated by
`Sensitive` and `SensitiveDual` clone the value, redact the clone, and serialize
it, so through them `.slog_redacted()`, `.slog_redacted_json()`, and
`.tracing_redacted()` inherit every `Clone` panic: a traversed `RefCell` with a
live mutable borrow panics at the log call. `.slog_redacted_json()` and
`.tracing_redacted()` run the producer at the call; `.slog_redacted()` borrows
the value and runs it each time slog serializes the record. The display
producers generated by
`SensitiveDisplay` and `NotSensitiveDisplay` format the borrowed value and need
no `Clone`; `SensitiveDisplay` goes through the crate's formatter, which renders
a mutably borrowed `RefCell` as `<borrowed>`, while `NotSensitiveDisplay` uses
the type's own `Display`, including its borrow behavior. `NotSensitive`
serializes the borrowed value, and the Bypass wrappers inherit the behavior of
what they wrap. There is no consuming route to a `RedactedValue`; the consuming
`into_tracing_*` adapters remain for the `Debug` and `Valuable` paths.

Those consuming adapters call `.redact()` on the owned value and accept every
`Redactable` shape. Traversal may still clone shared `Arc` or `Rc` referents and
map or set hashers. A live `RefCell` mutable borrow behind shared ownership can
therefore still panic. Prefer `Box` when the logged value has unique ownership.

A `Sensitive` type always produces JSON. On serialization failure, the JSON is
the fixed string `"[REDACTED]"`; serializer errors and input data are never
included.

Derive `Clone` and Serde's `Serialize` alongside `Sensitive` and the JSON is
generated. Add `serde_json = "1"` as a direct dependency for the sink. The sink
below reads both representations of the same value:

```rust
use redactable::{BypassDisplayRedaction, Email, Sensitive, ToRedacted};
use serde::Serialize;

#[derive(Clone, Sensitive, Serialize)]
struct LoginResult {
    #[sensitive(Email)]
    owner: String,
    #[not_sensitive]
    accepted: bool,
}

fn capture(value: &impl ToRedacted) -> String {
    value.to_redacted().text()
}

let result = LoginResult { owner: "alice@example.com".into(), accepted: true };
assert_eq!(capture(&result), r#"{"accepted":true,"owner":"al***@example.com"}"#);
assert_eq!(
    result.to_redacted().json(),
    serde_json::json!({"accepted": true, "owner": "al***@example.com"})
);

// A plain string reaches the same sink through an explicit escape.
let public = BypassDisplayRedaction("public readiness message");
assert_eq!(capture(&public), "public readiness message");
assert_eq!(
    public.to_redacted().json(),
    serde_json::json!({"message": "public readiness message"})
);
```

For `SensitiveDual`, one `RedactedValue` carries both representations: `text()`
is the redacted template and `json()` is the redacted object, while
`.redacted_display()` still returns the template view. `.slog_redacted()` and
`.tracing_redacted()` render the template; `.slog_redacted_json()` renders the
object.

With `testing` (and the default `redaction` feature),
`testing::assert_json_shape` compares object keys, array lengths and
corresponding elements, and scalar JSON kinds. It reads the value's `json()`, so
a text-only producer is compared as `{"message": …}`. Pair it with an
independently written expected JSON value and public sentinel assertions. Strict
JSON Pointer paths can mark opaque nodes; their parents still require the node
on both sides. Malformed paths are rejected. Valid paths beneath absent options,
empty collections, or scalar parents can remain inactive, so include populated
samples. Shape alone does not prove correct redaction.

`RedactedList::new(&items, limit)` accepts `T: ToRedacted` and an explicit
`NonZeroUsize` item limit, and produces `{"items":[...],"omitted":count}`. Each
included item is its `json()`, so a text item appears as `{"message": …}` and a
JSON item keeps its value. Only included producers run, once each in order. The
omitted count is visible. The limit does not bound total bytes, depth,
allocations, or policy cost.

## Reference

### Supported types

`#[sensitive(Policy)]` supports `String`, `Cow<'_, str>`, and wrappers such as
`Option<String>`. Borrowed redaction of `Cow<'_, str>` returns an owned
`Cow<'static, str>`. `Sensitive` does not support `&str`; use an owned string or
`Cow`.

`#[sensitive(Secret)]` supports scalars: integers become `0`, floats become
`0.0`, `bool` becomes `false`, and `char` becomes `'*'`. `NonZero*` integers
cannot be policy-annotated because redaction may need to produce zero.

Supported containers are walked automatically. Policy annotations recurse
through options, sequences, arrays, results, maps, and sets. Map keys are not
redacted. Generated formatting invokes each key's compact or alternate `Debug`
implementation exactly once.

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
`redaction` is a default feature and now pulls in `serde` and `serde_json`;
`json` is kept as a compatibility alias that enables it.

The API trait implementation lists are authoritative for individual types and
feature gates.

### Advanced derive options

Most types need no `#[redactable(...)]` field option. The derive macros expose
three narrow overrides for shapes that procedural macros cannot infer on stable
Rust:

- `recursive` suppresses a cyclic inferred bound on a recursive field.
- `generated_formatting` selects the library formatter for an alias-hidden
  built-in container.
- `legacy_formatting` selects a custom `PolicyApplicableRef` projection.

These three options apply only to fields, and the formatting options require
`#[sensitive(Policy)]` on the same field. `legacy_formatting` inherits the
custom projection's `Clone` and `RefCell` behavior. Generated text/secret
formatting borrows map keys. Custom `PolicyApplicableRef` leaves used directly
by `SensitiveDisplay` must also implement the formatting companion described in
the [`SensitiveDisplay` API
documentation](https://docs.rs/redactable/latest/redactable/derive.SensitiveDisplay.html).

Direct generic calls to the legacy `PolicyApplicable` methods require
`P::Kind: RecursivePolicyKind`. Use the kind-aware `apply_policy` and
`apply_policy_ref` free functions when `P` may be an IP policy. The borrowed
free function uses ordinary `RefCell` borrowing and can panic on a conflicting
mutable borrow; generated formatting renders `<borrowed>` instead.

### Precedence and edge cases

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
rejected, and each rejection names the field placement that would be valid. The
removed `#[redactable(output = json)]` has its own migration diagnostic:
`Sensitive` and `SensitiveDual` now produce JSON without it.

**Sets can collapse:** redacted elements are collected back into a set. If
several values become equal, the result shrinks. Use a `Vec` when cardinality
must be preserved.

### Built-in policies

| Policy | Use for | Example output |
|---|---|---|
| `Secret` | Scalars or generic redaction | `0` / `false` / `'*'` / `[REDACTED]` |
| `Token` | API keys | `************f456` (last 4) |
| `Email` | Email addresses | `al***@example.com` |
| `CreditCard` | Card numbers | `************1234` (last 4) |
| `Pii` | Generic PII (names, addresses) | `******oe` (last 2) |
| `PhoneNumber` | Phone numbers | `*******4567` (last 4) |
| `IpAddress` | IP addresses | `0.0.0.100` (last IPv4 octet) |
| `BlockchainAddress` | Wallet addresses | `************abcdef` (last 6) |

### Custom policies

```rust
use redactable::{RedactionPolicy, TextPolicyKind, TextRedactionPolicy};

#[derive(Clone, Copy)]
struct InternalId;

impl RedactionPolicy for InternalId {
    type Kind = TextPolicyKind;

    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(2)
    }
}
```
