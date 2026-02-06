# Redactable

`redactable` is a redaction library for Rust. It lets you mark sensitive data in your structs and enums and produce a safe, redacted version of the same type. Logging and telemetry are the most common use cases, but redaction is not tied to any logging framework.

## Table of Contents

- [Core traits](#core-traits)
- [Design philosophy](#design-philosophy)
- [How it works](#how-it-works)
- [Walkthrough](#walkthrough)
  - [Trait bounds on containers](#trait-bounds-on-containers)
  - [Blanket implementations](#blanket-implementations)
  - [The `#[sensitive(Policy)]` attribute](#the-sensitivepolicy-attribute)
  - [How `RedactableLeaf` fits in](#how-redactableleaf-fits-in)
  - [Opting out with `NotSensitive`](#opting-out-with-notsensitive)
    - [`NotSensitiveDisplay` - Full logging integration](#notsensitivedisplay---full-logging-integration)
  - [Wrapper types for foreign types](#wrapper-types-for-foreign-types)
- [Sensitive vs SensitiveDisplay](#sensitive-vs-sensitivedisplay)
  - [Sensitive (structured redaction)](#sensitive-structured-redaction)
  - [SensitiveDisplay (string formatting)](#sensitivedisplay-string-formatting)
- [SensitiveDisplay in depth](#sensitivedisplay-in-depth)
  - [Template syntax](#template-syntax)
  - [Field annotations](#field-annotations)
- [Decision guide](#decision-guide)
- [Logging output (explicit boundary)](#logging-output-explicit-boundary)
  - [Wrapper safety at the boundary](#wrapper-safety-at-the-boundary)
- [Integrations](#integrations)
  - [slog](#slog)
  - [tracing](#tracing)
  - [Sink-specific safety traits](#sink-specific-safety-traits)
- [Logging with maximum security](#logging-with-maximum-security)
  - [The logging footgun](#the-logging-footgun)
  - [Built-in safety with slog and tracing](#built-in-safety-with-slog-and-tracing)
  - [Enforcing safety with trait bounds](#enforcing-safety-with-trait-bounds)
  - [Alternative: `SensitiveValue<T, P>` wrappers](#alternative-sensitivevaluet-p-wrappers)
  - [Trade-offs: attributes vs wrappers](#trade-offs-attributes-vs-wrappers)
  - [Choosing an approach](#choosing-an-approach)
- [Reference](#reference)
  - [Trait map](#trait-map)
  - [Supported types](#supported-types)
  - [Precedence and edge cases](#precedence-and-edge-cases)
  - [Built-in policies](#built-in-policies)
  - [Custom policies](#custom-policies)
- [License](#license)

## Core traits

- `RedactableContainer`: composite types (structs, enums) that are traversed field-by-field
- `RedactableLeaf`: terminal values that can be converted to/from a string for redaction
- `RedactionPolicy`: types that define how a leaf is transformed (full redaction, keep last N chars, etc.)

## Design philosophy

- **Traversal is automatic**: nested containers are handled automatically. For `Sensitive`, they're walked via `RedactableContainer`. For `SensitiveDisplay`, they're formatted via `RedactableDisplay`.
- **Redaction is opt-in**: leaf values (scalars, strings) pass through unchanged unless explicitly marked with `#[sensitive(Policy)]`. Redaction only happens where you ask for it.
- **Consistent annotation workflow**: both `Sensitive` and `SensitiveDisplay` follow the same pattern - unannotated scalars pass through, unannotated containers are handled via their trait, and `#[sensitive(Policy)]` applies redaction.
- **Types are preserved**: `Sensitive`'s `.redact()` returns the same type, not a string or wrapper.

## How it works

The `Sensitive` derive macro generates traversal code. For each field, it calls `RedactableContainer::redact_with`. This uniform interface is what makes everything compose.

| Field kind | What happens |
|------------|--------------|
| **Containers** (structs/enums deriving `Sensitive`) | Traversal walks into them recursively, visiting each field |
| **Unannotated leaves** (String, primitives, etc.) | These implement `RedactableContainer` as a passthrough - they return themselves unchanged |
| **Annotated leaves** (`#[sensitive(Policy)]`) | The macro generates transformation code that applies the policy, bypassing the normal `RedactableContainer::redact_with` call |
| **Explicit passthrough** (`#[not_sensitive]`) | Field is left unchanged without requiring `RedactableContainer` - use for foreign types |

```rust
#[derive(Clone, Sensitive)]
struct User {
    address: Address,       // container → walks into it
    name: String,           // leaf, no annotation → passthrough (unchanged)
    #[sensitive(Token)]
    api_key: String,        // leaf, annotated → policy applied (redacted)
}
```

This is why every field must implement `RedactableContainer`: containers need it for traversal, and leaves provide passthrough implementations that satisfy the requirement without doing anything.

`SensitiveDisplay` follows the same principle but uses `RedactableDisplay` instead: nested types format via their `fmt_redacted()` method, and scalars pass through unchanged. See [SensitiveDisplay in depth](#sensitivedisplay-in-depth) for details.

## Walkthrough

### Trait bounds on containers

As described in [How it works](#how-it-works), every field must implement `RedactableContainer`. Here's what that looks like in practice:

```rust
#[derive(Clone, Sensitive)]
struct Address {
    city: String,
}

#[derive(Clone, Sensitive)]
struct User {
    address: Address,  // ✅ Address implements RedactableContainer (from Sensitive derive)
}
```

If a field's type does not implement `RedactableContainer`, you get a compilation error:

```rust
struct Account {  // Does NOT derive Sensitive
    password: String,
}

#[derive(Clone, Sensitive)]
struct Session {
    account: Account,  // ❌ ERROR: Account does not implement RedactableContainer
}
```

### Blanket implementations

Two kinds of types get `RedactableContainer` for free.

#### Standard leaf types

`String`, primitives (`u32`, `bool`, etc.) implement `RedactableContainer` as a passthrough - they return themselves unchanged. This is why unannotated leaves compile and are left as-is:

```rust
#[derive(Clone, Sensitive)]
struct Profile {
    name: String,  // passthrough, unchanged
    age: u32,      // passthrough, unchanged
}

let profile = Profile { name: "alice".into(), age: 30 };
let redacted = profile.redact();
assert_eq!(redacted.name, "alice");
assert_eq!(redacted.age, 30);
```

#### Standard container types

`Option`, `Vec`, `Box`, `Arc`, etc. implement `RedactableContainer` by calling `redact_with` on their inner value(s). They do **not** change how the inner value is treated: the inner type (and any `#[sensitive(...)]` on the leaf value) decides whether it is a leaf, a nested container, or classified. Some examples:

- `Option<String>` still treats the `String` as a passthrough leaf
- `Option<MyStruct>` still walks into `MyStruct`
- `#[sensitive(Secret)]` on an `Option<String>` leaf applies the policy to the string inside

```rust
#[derive(Clone, Sensitive)]
struct Inner {
    #[sensitive(Secret)]
    secret: String,
}

#[derive(Clone, Sensitive)]
struct Outer {
    maybe_string: Option<String>,  // Option walks, inner String is passthrough → unchanged
    maybe_inner: Option<Inner>,    // Option walks, inner Inner is walked → secret redacted
    #[sensitive(Secret)]
    secret: Option<String>,        // #[sensitive] applies policy through the Option
}

let outer = Outer {
    maybe_string: Some("visible".into()),
    maybe_inner: Some(Inner { secret: "hidden".into() }),
    secret: Some("also_hidden".into()),
};
let redacted = outer.redact();

assert_eq!(redacted.maybe_string, Some("visible".into()));      // unchanged
assert_eq!(redacted.maybe_inner.unwrap().secret, "[REDACTED]"); // walked and redacted
assert_eq!(redacted.secret, Some("[REDACTED]".into()));         // policy applied
```

### The `#[sensitive(Policy)]` attribute

The `#[sensitive(Policy)]` attribute marks a leaf as sensitive and applies a redaction policy. When present, the derive macro generates transformation code that applies the policy directly, bypassing the normal `redact_with` passthrough:

- `#[sensitive(Secret)]` on scalars: replaces the value with a default (0, false, `'*'`)
- `#[sensitive(Secret)]` on strings: replaces with `"[REDACTED]"`
- `#[sensitive(Policy)]` on strings: applies the policy's redaction rules

```rust
#[derive(Clone, Sensitive)]
struct Login {
    username: String,           // unchanged
    #[sensitive(Secret)]
    password: String,           // redacted to "[REDACTED]"
    #[sensitive(Secret)]
    attempts: u32,              // redacted to 0
}
```

#### ⚠️ Qualified primitive paths don't work with `#[sensitive(Secret)]`

The derive macro decides how to handle `#[sensitive(Secret)]` based on a **syntactic check** of how you wrote the type. Only bare primitive names like `u32`, `bool`, `char` are recognized as scalars. Qualified paths like `std::primitive::u32` are not.

This matters because:

- **Unannotated leaves**: Both `u32` and `std::primitive::u32` work identically (passthrough via `RedactableContainer`)
- **`#[sensitive(Secret)]` leaves**:
  - `u32` → recognized as scalar → redacts to `0` ✅
  - `std::primitive::u32` → not recognized → tries to use `PolicyApplicable` → **compile error** ❌

```rust
#[derive(Clone, Sensitive)]
struct Example {
    #[sensitive(Secret)]
    count: u32,                    // ✅ works: recognized as scalar, redacts to 0

    #[sensitive(Secret)]
    other: std::primitive::u32,    // ❌ compile error: u32 doesn't implement PolicyApplicable
}
```

**Workaround**: Always use bare primitive names (`u32`, `bool`, etc.) when applying `#[sensitive(Secret)]`.

### How `RedactableLeaf` fits in

When you write `#[sensitive(Policy)]`, the generated code needs to:
1. Extract a string from the value (to apply the policy)
2. Reconstruct the original type from the redacted string (so you get back your original type, not `String`)

`RedactableLeaf` provides this interface:

```rust
use redactable::RedactableLeaf;

struct UserId(String);

impl RedactableLeaf for UserId {
    fn as_str(&self) -> &str { &self.0 }                        // extract string
    fn from_redacted(redacted: String) -> Self { Self(redacted) } // reconstruct type
}
```

`String` already implements `RedactableLeaf`, which is why `#[sensitive(Token)]` works on `String` leaves out of the box. Implement it for your own types if you want policies to work on them.

### Opting out with `NotSensitive`

Some types you own need to satisfy `RedactableContainer` bounds but have no sensitive data. Use `#[derive(NotSensitive)]` to generate a no-op `RedactableContainer` impl:

```rust
use redactable::{NotSensitive, Sensitive};

#[derive(Clone, NotSensitive)]
struct PublicMetadata {
    version: String,
    timestamp: u64,
}

#[derive(Clone, Sensitive)]
struct Config {
    metadata: PublicMetadata,  // ✅ Works because NotSensitive provides RedactableContainer
}
```

> **Note:** `NotSensitive` is for types used with the `Sensitive` derive. For `SensitiveDisplay`, you have two options: use `#[derive(NotSensitiveDisplay)]` for a type with no sensitive data that needs logging integration (symmetric with `SensitiveDisplay`), or use the `#[not_sensitive]` field attribute when only some fields need to opt out.

> **Debug:** `NotSensitive` does not generate a `Debug` impl. If your type previously derived `Sensitive` (which generates `Debug`) and you switch to `NotSensitive`, add `#[derive(Debug)]` explicitly — `Sensitive` containers require `Debug` on all field types. Since the data is non-sensitive, standard `#[derive(Debug)]` is safe. `NotSensitiveDisplay` does generate `Debug`, so this only applies to `NotSensitive`.

#### `NotSensitiveDisplay` - Full logging integration

When you need logging integration (slog, tracing) for a type with no sensitive data, use `NotSensitiveDisplay`. This is the display counterpart to `NotSensitive`:

```rust
use redactable::NotSensitiveDisplay;

/// Retry using backoff
#[derive(Clone, NotSensitiveDisplay)]
enum RetryDecision {
    Retry { delay_ms: u64 },
    Abort,
}

impl std::fmt::Display for RetryDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retry { delay_ms } => write!(f, "Retry after {}ms", delay_ms),
            Self::Abort => write!(f, "Abort"),
        }
    }
}
```

`NotSensitiveDisplay` generates:
- `RedactableContainer` - no-op passthrough (allows use inside `Sensitive` containers)
- `RedactableDisplay` - delegates to `Display::fmt`
- `Debug` - production uses `Display`, test builds use standard `Debug` (use `#[not_sensitive_display(skip_debug)]` to opt out)
- `slog::Value` and `SlogRedacted` - when `slog` feature is enabled
- `TracingRedacted` - when `tracing` feature is enabled

`NotSensitiveDisplay` is a strict superset of `NotSensitive` — it provides everything `NotSensitive` does (`RedactableContainer`) plus `RedactableDisplay`, `Debug`, and logging integration. For any non-sensitive type that has `Display`, prefer `NotSensitiveDisplay`: it works everywhere `NotSensitive` works (as fields in `Sensitive` containers) and additionally supports direct logging.

This is useful when combining with `displaydoc` or similar crates that derive `Display`:

```rust
use redactable::NotSensitiveDisplay;

#[derive(Clone, displaydoc::Display, NotSensitiveDisplay)]
enum RetryDecision {
    /// Retry using backoff
    Retry,
    /// Do not retry
    Abort,
}
// Now RetryDecision has Display (from displaydoc), RedactableDisplay, slog::Value, etc.
```

### Wrapper types for foreign types

Two wrapper types handle types you don't own (Rust's orphan rules prevent deriving `Sensitive` or implementing `RedactableLeaf` on foreign types):

- **`NotSensitiveValue<T>`**: Wraps T and passes through unchanged
- **`SensitiveValue<T, P>`**: Wraps T and applies policy P when redacted

#### Foreign types with no sensitive data

Use `NotSensitiveValue<T>` to satisfy `RedactableContainer` bounds:

```rust
use redactable::{NotSensitiveValue, Sensitive};

struct ForeignConfig { timeout: u64 }  // (pretend this is from another crate)

#[derive(Clone, Sensitive)]
struct AppConfig {
    foreign: NotSensitiveValue<ForeignConfig>,  // Passes through unchanged
}
```

#### Foreign leaf types that need redaction

For string-like foreign types (IDs, tokens), use `RedactableWithPolicy<P>` with `SensitiveValue<T, P>`:

```rust
// ❌ ERROR: can't implement RedactableLeaf (foreign trait) for ForeignId (foreign type)
impl RedactableLeaf for other_crate::ForeignId { ... }

// ✅ OK: RedactableWithPolicy<MyPolicy> is "local enough" because MyPolicy is yours
impl RedactableWithPolicy<MyPolicy> for other_crate::ForeignId { ... }
```

Then wrap the leaf:

```rust
#[derive(Clone, Sensitive)]
struct Config {
    foreign_id: SensitiveValue<other_crate::ForeignId, MyPolicy>,
}
```

Here's a complete example:

```rust
use redactable::{RedactableWithPolicy, RedactionPolicy, SensitiveValue, TextRedactionPolicy};

#[derive(Clone)]
struct ForeignId(String);  // (pretend this comes from another crate)

// 1. Define a local policy (can reuse built-in logic)
#[derive(Clone, Copy)]
struct ForeignIdPolicy;
impl RedactionPolicy for ForeignIdPolicy {
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(2)
    }
}

// 2. Implement RedactableWithPolicy for the foreign type
impl RedactableWithPolicy<ForeignIdPolicy> for ForeignId {
    fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self {
        Self(policy.apply_to(&self.0))
    }

    fn redacted_string(&self, policy: &TextRedactionPolicy) -> String {
        policy.apply_to(&self.0)
    }
}

// 3. Create a type alias for ergonomics
type SensitiveForeignId = SensitiveValue<ForeignId, ForeignIdPolicy>;

// 4. Use the alias
let wrapped = SensitiveForeignId::from(ForeignId("external".into()));
```

⚠️ **Wrappers treat their inner type as a leaf, not a container.** Neither walks nested containers - if T derives `Sensitive`, its internal `#[sensitive(...)]` annotations would *not* be applied. This is ok because if a type derives `Sensitive` it should not be wrapped.

💡 **These wrappers can also be used for types you own** to provide additional logging safety guarantees. See [Logging with maximum security](#logging-with-maximum-security) for details.

## Sensitive vs SensitiveDisplay

There are two derive macros for redaction, plus their non-sensitive counterparts. Pick the one that matches your constraints:

| | `Sensitive` | `SensitiveDisplay` |
|---|---|---|
| **Output** | Same type with redacted leaves | Redacted string |
| **Ownership** | Consumes `self` (clone if you need the original) | Borrows `self` |
| **Traverses containers** | Yes (walks all fields) | No (only template placeholders) |
| **Unannotated scalars** | Passthrough | Passthrough |
| **Unannotated containers** | Walked via `RedactableContainer` | Formatted via `RedactableDisplay` |
| **Best for** | Structured data | Display strings, non-Clone types |

### Sensitive (structured redaction)

Use `Sensitive` when you can consume the value (or clone it if you need the original). Nested containers are traversed automatically; leaves are only redacted when annotated with `#[sensitive(Policy)]`.

```rust
use redactable::Sensitive;

#[derive(Clone, Sensitive)]
struct LoginAttempt {
    user: String,                // unchanged (no annotation)
    #[sensitive(Secret)]
    password: String,            // redacted to "[REDACTED]"
}

let attempt = LoginAttempt {
    user: "alice".into(),
    password: "hunter2".into(),
};
let redacted = attempt.redact();
assert_eq!(redacted.user, "alice");
assert_eq!(redacted.password, "[REDACTED]");
```

### SensitiveDisplay (string formatting)

Use `SensitiveDisplay` when you need a redacted string representation without `Clone`. It formats from a template and uses `RedactableDisplay` for unannotated placeholders. Common scalar-like types implement `RedactableDisplay` as passthrough.

```rust
use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
enum LoginError {
    #[error("login failed for {user} {password}")]
    Invalid {
        user: String,               // passthrough by default
        #[sensitive(Secret)]       // redacted to "[REDACTED]"
        password: String,
    },
}

let err = LoginError::Invalid {
    user: "alice".into(),
    password: "hunter2".into(),
};
// err.redacted_display() → "login failed for alice [REDACTED]"
```

`SensitiveDisplay` also derives a conditional `Debug` impl: in production builds it formats via
`RedactableDisplay::fmt_redacted`, while test/testing builds show actual values for debugging.
Use `#[sensitive(skip_debug)]` to opt out if you need a custom `Debug`.

See [SensitiveDisplay in depth](#sensitivedisplay-in-depth) for template syntax and field annotations.

Nested `SensitiveDisplay` types are redacted automatically without extra annotations:

```rust
use redactable::{Secret, SensitiveDisplay};

#[derive(SensitiveDisplay)]
enum InnerError {
    #[error("db password {password}")]
    BadPassword {
        #[sensitive(Secret)]
        password: String,
    },
}

#[derive(SensitiveDisplay)]
enum OuterError {
    #[error("request failed: {source}")]
    RequestFailed { source: InnerError },
}

let err = OuterError::RequestFailed {
    source: InnerError::BadPassword {
        password: "secret".into(),
    },
};
// err.redacted_display() → "request failed: db password [REDACTED]"
```

## SensitiveDisplay in depth

`SensitiveDisplay` derives `RedactableDisplay`, which provides `fmt_redacted()` and `redacted_display()`. Unlike `Sensitive`, it produces a string rather than a redacted copy of the same type.

The annotation workflow mirrors `Sensitive`:
- **Unannotated scalars** → passthrough (unchanged)
- **Unannotated nested types** → use their `RedactableDisplay` implementation
- **`#[sensitive(Policy)]`** → apply redaction policy

### Template syntax

The display template comes from one of two sources:

**1. `#[error("...")]` attribute** (thiserror-style):

```rust
#[derive(SensitiveDisplay)]
enum ApiError {
    #[error("auth failed for {user}")]
    AuthFailed { user: String },
}
```

**2. Doc comment** (displaydoc-style):

```rust
#[derive(SensitiveDisplay)]
enum ApiError {
    /// auth failed for {user}
    AuthFailed { user: String },
}
```

Both support:
- Named placeholders: `{field_name}`
- Positional placeholders: `{0}`, `{1}`
- Debug formatting: `{field:?}`

### Field annotations

Unannotated placeholders use `RedactableDisplay`:

| Annotation | Behavior |
|---|---|
| *(none)* | Uses `RedactableDisplay`: scalars pass through unchanged; nested `SensitiveDisplay` types are redacted |
| `#[not_sensitive]` | Renders with raw `Display` (or `Debug` if `{:?}`) - use for types without `RedactableDisplay` |
| `#[sensitive(Secret)]` | Scalars → default value; strings → `"[REDACTED]"` |
| `#[sensitive(Policy)]` | Applies the policy's redaction rules |

This matches `Sensitive` behavior: scalars pass through, nested containers use their redaction trait. Both `Sensitive` and `SensitiveDisplay` support all these annotations.

Unannotated fields that do not implement `RedactableDisplay` produce a compile error:

```rust
struct ExternalContext;

impl std::fmt::Display for ExternalContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("external")
    }
}

#[derive(SensitiveDisplay)]
enum LoginError {
    #[error("context {ctx}")]
    Failed {
        ctx: ExternalContext,  // ❌ ERROR: does not implement RedactableDisplay
    },
}
```

This prevents accidental exposure when adding new fields while still making nested redaction ergonomic.

## Decision guide

**Which derive macro?**

1. **Does the type contain sensitive data?**
   - Yes → `Sensitive` or `SensitiveDisplay`
   - No → `NotSensitive` or `NotSensitiveDisplay`

2. **Sensitive types: structured data or display string?**
   - Structured data you can clone → `Sensitive`
   - Display string, errors, or non-Clone types → `SensitiveDisplay`

3. **Non-sensitive types: does it have `Display`?**
   - Yes → `NotSensitiveDisplay` (provides container, Debug, and logging — strict superset of `NotSensitive`)
   - No → `NotSensitive` + explicit `#[derive(Debug)]`

**What each derive generates:**

| Derive | `RedactableContainer` | `RedactableDisplay` | `Debug` | Logging |
|---|---|---|---|---|
| `Sensitive` | ✅ | ❌ | ✅ | ✅ |
| `NotSensitive` | ✅ | ❌ | ❌ | ❌ |
| `SensitiveDisplay` | ❌ | ✅ | ✅ | ✅ |
| `NotSensitiveDisplay` | ✅ | ✅ | ✅ | ✅ |

- **Debug** is conditional: production builds show redacted/Display output; test builds show actual values. Opt out with `skip_debug`.
- **Logging** = `slog::Value` + `SlogRedacted` (requires `slog` feature), `TracingRedacted` (requires `tracing` feature). For `Sensitive`, slog integration requires `Serialize` on the type (the redacted struct is serialized as JSON).
- `SensitiveDisplay` and `NotSensitiveDisplay` require `Display` on the type.
- `Sensitive` conventionally pairs with `Clone` since `.redact()` consumes `self`.

**Common patterns:**

- **Newtype wrappers** (e.g., `struct Name(String)`) with `Display` → `NotSensitiveDisplay`
- **Fieldless enums** used as classifiers with `Display` (via `strum` or manual impl) → `NotSensitiveDisplay`
- **Composite structs** with multiple fields, no `Display` → `NotSensitive` + `#[derive(Debug)]`
- **Error types with sensitive data** (PII in fields, user input in messages) → `SensitiveDisplay` with `#[sensitive(Policy)]` on sensitive fields
- **Error types with no sensitive data** (operational, infrastructure) → `NotSensitiveDisplay`

**How to opt out of redaction?**

| Context | Situation | Use |
|---|---|---|
| `Sensitive` | Type you own, no sensitive data | `#[derive(NotSensitive)]` |
| `Sensitive` | Foreign type in a field | `#[not_sensitive]` attribute or `NotSensitiveValue<T>` wrapper |
| `SensitiveDisplay` | Type you own, no sensitive data + need logging | `#[derive(NotSensitiveDisplay)]` |
| `SensitiveDisplay` | Field without `RedactableDisplay` | `#[not_sensitive]` attribute (uses raw `Display`) |

**How to handle foreign types that need redaction?**

| Situation | Use |
|---|---|
| Foreign leaf type with policy | `SensitiveValue<T, Policy>` + `RedactableWithPolicy` |

**How to produce logging output?**

| Situation | Use |
|---|---|
| Container → redacted text | `.redacted_output()` |
| Container → redacted JSON | `.redacted_json()` (requires `json` feature) |
| Non-sensitive value (explicit Display) | `.not_sensitive_display()` |
| Non-sensitive value (explicit Debug) | `.not_sensitive_debug()` |
| Non-sensitive value (explicit JSON) | `.not_sensitive_json()` (requires `json` feature) |
| Non-sensitive value (delegate to framework) | `.not_sensitive()` |
| SensitiveDisplay type | `.redacted_display()` or `.to_redacted_output()` |

**Which not_sensitive method should I use?**

| Method | Trait requirement | Returns | Use when |
|---|---|---|---|
| `.not_sensitive()` | None | `NotSensitive<&Self>` | Type already implements `slog::Value` or you want the logging framework to decide formatting |
| `.not_sensitive_display()` | `T: Display` | `NotSensitiveDisplay<&T>` | You want explicit `Display` formatting, works with any type |
| `.not_sensitive_debug()` | `T: Debug` | `NotSensitiveDebug<&T>` | You want explicit `Debug` formatting, works with any type |
| `.not_sensitive_json()` | `T: Serialize` | `NotSensitiveJson<&T>` | You want structured JSON output (requires `json` feature) |

**Important:** `.not_sensitive()` is a thin wrapper that delegates formatting to the logging framework. It only works with slog when `T: slog::Value`. If your type doesn't implement `slog::Value`, use `.not_sensitive_display()` or `.not_sensitive_debug()` instead - they work with any type that implements `Display` or `Debug` respectively.

## Logging output (explicit boundary)

`ToRedactedOutput` is the single logging-safe bound. It produces a `RedactedOutput`:

- `RedactedOutput::Text(String)`
- `RedactedOutput::Json(serde_json::Value)` (requires the `json` feature)

⚠️ **The Json variant uses `serde_json::Value`**, which integrates well with slog's structured logging. For tracing, the Json variant is converted to a string since tracing's `Value` trait is sealed.

Several wrappers produce `RedactedOutput`:

- `SensitiveValue<T, Policy>` (Text)
- `RedactedOutputRef` / `.redacted_output()` (Text)
- `RedactedJsonRef` / `.redacted_json()` (Json, `json` feature)
- `NotSensitiveDisplay` / `.not_sensitive_display()` (Text)
- `NotSensitiveDebug` / `.not_sensitive_debug()` (Text)
- `NotSensitiveJson` / `.not_sensitive_json()` (Json, `json` feature)

Use `.not_sensitive()` when the type already implements `slog::Value` or you want to
delegate formatting to the logging framework. It borrows `&self`, returning `NotSensitive<&Self>`.
The wrapper:
- Implements `Deref<Target = T>` for ergonomic access
- Implements `Display` when `T: Display` and `Debug` when `T: Debug`
- Implements `slog::Value` when `T: slog::Value` (delegates to inner value's serialization)
- Does **not** implement `ToRedactedOutput` (use `.not_sensitive_display()` or `.not_sensitive_debug()` if you need that)

⚠️ **If your type doesn't implement `slog::Value`, using `.not_sensitive()` with slog will give
a compile error.** In that case, use `.not_sensitive_display()` or `.not_sensitive_debug()` instead,
which work with any `Display` or `Debug` type respectively.

### Wrapper safety at the boundary

Types that guarantee redaction for a sink implement the sink marker traits
(`SlogRedacted`, `TracingRedacted`). In practice:

- Guaranteed redaction (by definition or adapter): `SensitiveValue<T, Policy>`, `RedactedOutput`, `RedactedOutputRef`,
  `RedactedJsonRef` (json), plus sink-specific wrappers like `slog::RedactedJson` and
  `tracing::RedactedValuable` (with `tracing-valuable`)
- Derived types: `Sensitive`, `SensitiveDisplay`, and `NotSensitiveDisplay` implement the marker traits when the sink
  feature is enabled
- Explicitly non-sensitive: `NotSensitive<T>` (when `T: SlogRedacted`/`TracingRedacted`),
  `NotSensitiveDisplay<T>`, `NotSensitiveDebug<T>`, `NotSensitiveJson<T>` wrapper types (you are asserting safety)
- Not a guarantee: raw `String`/scalars and passthrough `RedactableDisplay` types

```rust
use redactable::{
    NotSensitiveDebugExt, NotSensitiveDisplayExt, NotSensitiveJsonExt, RedactedJsonExt,
    RedactedOutput, RedactedOutputExt, RedactableLeaf, SensitiveValue, Sensitive, Secret,
    ToRedactedOutput,
};

#[derive(Clone)]
struct ExternalId(String);

impl RedactableLeaf for ExternalId {
    fn as_str(&self) -> &str { self.0.as_str() }
    fn from_redacted(redacted: String) -> Self { Self(redacted) }
}

#[derive(Clone, Sensitive)]
struct Event {
    id: SensitiveValue<ExternalId, Secret>,
    status: String,
}

fn log_redacted<T: ToRedactedOutput>(value: &T) {
    match value.to_redacted_output() {
        RedactedOutput::Text(text) => println!("{}", text),
        #[cfg(feature = "json")]
        RedactedOutput::Json(json) => println!("{}", json),
    }
}

let event = Event {
    id: SensitiveValue::from(ExternalId("abc".into())),
    status: "ok".into(),
};

log_redacted(&event.id);

log_redacted(&event.status.not_sensitive_display());
log_redacted(&event.status.not_sensitive_debug());
#[cfg(feature = "json")]
log_redacted(&event.status.not_sensitive_json());

let safe_status = event.status.not_sensitive();
let _ = format!("{safe_status}");
let _ = format!("{safe_status:?}");

log_redacted(&event.redacted_output());
#[cfg(feature = "json")]
log_redacted(&event.redacted_json());
```

Notes:

- `redacted_output()` uses `Debug` formatting on the redacted value; `redacted_json()` provides structured output when JSON is available
- This crate does not override `Display`, so bypassing `ToRedactedOutput` and logging raw values directly can still leak data
- For stronger guarantees, route all logging through helpers that require `T: ToRedactedOutput`

## Integrations

### slog

The `slog` feature enables automatic redaction - just log your values and they're redacted:

```toml
[dependencies]
redactable = { version = "0.5", features = ["slog"] }
```

**Containers** - the `Sensitive` derive generates `slog::Value` automatically:

```rust
#[derive(Clone, Sensitive, Serialize)]
struct PaymentEvent {
    #[sensitive(Email)]
    customer_email: String,
    #[sensitive(CreditCard)]
    card_number: String,
    amount: u64,
}

let event = PaymentEvent {
    customer_email: "alice@example.com".into(),
    card_number: "4111111111111234".into(),
    amount: 9999,
};

// Just log it - slog::Value impl handles redaction automatically
slog::info!(logger, "payment"; "event" => &event);
// Logged JSON: {"customer_email":"al***@example.com","card_number":"************1234","amount":9999}
```

**Leaf wrappers** - `SensitiveValue<T, P>` also implements `slog::Value`:

```rust
let api_token: SensitiveValue<String, Token> = SensitiveValue::from("sk-secret-key".into());

// Also automatic - SensitiveValue has its own slog::Value impl
slog::info!(logger, "auth"; "token" => &api_token);
// Logged: "*********-key"
```

Both work because they implement `slog::Value` - containers via the derive macro, wrappers via a manual implementation. No explicit conversion needed. `SensitiveDisplay` and `NotSensitiveDisplay` types also derive `slog::Value` when the feature is enabled, emitting the (redacted) display string.

### tracing

For structured logging with tracing, use the `valuable` integration:

```toml
[dependencies]
redactable = { version = "0.5", features = ["tracing-valuable"] }
```

```rust
use redactable::tracing::TracingValuableExt;

#[derive(Clone, Sensitive, valuable::Valuable)]
struct AuthEvent {
    #[sensitive(Token)]
    api_key: String,
    #[sensitive(Email)]
    user_email: String,
    action: String,
}

let event = AuthEvent {
    api_key: "sk-secret-key-12345".into(),
    user_email: "alice@example.com".into(),
    action: "login".into(),
};

// Redacts and logs as structured data - subscriber can traverse containers
tracing::info!(event = event.tracing_redacted_valuable());
// Logged: {api_key: "***************2345", user_email: "al***@example.com", action: "login"}
```

Unlike slog where `slog::Value` can be implemented automatically via the derive macro, tracing's `Value` trait is sealed. The `valuable` crate provides the structured data path - `.tracing_redacted_valuable()` redacts first, then wraps for `valuable` inspection.

**For individual values** (without `valuable`):

```rust
use redactable::tracing::TracingRedactedExt;

let api_key: SensitiveValue<String, Token> = SensitiveValue::from("sk-secret-key-12345".into());
let user_email: SensitiveValue<String, Email> = SensitiveValue::from("alice@example.com".into());

tracing::info!(
    api_key = api_key.tracing_redacted(),
    user_email = user_email.tracing_redacted(),
    action = "login"
);
// Logged: api_key="***************2345" user_email="al***@example.com" action="login"
```

⚠️ **Note:** The `valuable` integration in tracing is still marked as unstable and requires a compatible subscriber.

### Sink-specific safety traits

`SlogRedacted` and `TracingRedacted` are marker traits that certify a type's output is redacted
for a specific sink. They indicate that the sink adapter uses the redacted path; they do not
validate policy choices.

They live in `redactable::slog` and `redactable::tracing` because the adapters differ
(`slog::Value` JSON vs tracing display/valuable). A type might be safe for one sink and not
the other.

The traits are implemented only next to the sink adapters (derive-generated impls and specific
wrappers), not as blanket impls for raw types or `ToRedactedOutput`. See
[Wrapper safety at the boundary](#wrapper-safety-at-the-boundary) for the covered wrappers.

## Logging with maximum security

For high-security domains (finance, healthcare, compliance-sensitive systems), you need guarantees that sensitive data can't be accidentally logged. This section explains the safety guarantees the library provides and how to leverage them.

### The logging footgun

With `#[sensitive(P)]` attributes, the field is still the bare type at runtime:

```rust
#[derive(Clone, Sensitive)]
struct User {
    #[sensitive(Pii)]
    email: String,  // At runtime, this is just a String
}

let user = User { email: "alice@example.com".into() };

// ❌ Nothing stops you from logging the field directly
log::info!("Email: {}", user.email);  // Logs "alice@example.com" unredacted!
```

This is the core problem: `#[sensitive(P)]` marks intent but doesn't change the runtime type.

### Built-in safety with slog and tracing

The library provides **automatic safety** when you use the slog or tracing integrations correctly. Types deriving `Sensitive` or `SensitiveDisplay` automatically implement `slog::Value` and the `SlogRedacted`/`TracingRedacted` marker traits.

**slog** - Just log containers directly:

```rust
#[derive(Clone, Sensitive, Serialize)]
struct User {
    #[sensitive(Pii)]
    email: String,
}

let user = User { email: "alice@example.com".into() };

// ✅ Safe: slog::Value impl auto-redacts before logging
slog::info!(logger, "user logged in"; "user" => &user);
// Logged: {"email":"al***@example.com"}
```

**tracing** - Use the extension traits:

```rust
use redactable::tracing::TracingValuableExt;

// ✅ Safe: redacts before logging as structured data
tracing::info!(user = user.tracing_redacted_valuable());
```

The footgun only happens when you bypass these integrations by logging individual fields directly (`user.email` instead of `&user`).

### Enforcing safety with trait bounds

The library provides marker traits that certify a type's output is redacted for a specific sink:

- `SlogRedacted` - implemented by types safe to log via slog
- `TracingRedacted` - implemented by types safe to log via tracing

These traits are implemented for:
- Types deriving `Sensitive`, `SensitiveDisplay`, or `NotSensitiveDisplay` (when the feature is enabled)
- `SensitiveValue<T, P>` wrappers
- `RedactedOutput`, `RedactedJson`, `RedactedOutputRef`, `RedactedJsonRef`
- `NotSensitive<T>` when `T` implements the marker trait (you assert safety)
- `NotSensitiveDisplay<T>`, `NotSensitiveDebug<T>`, `NotSensitiveJson<T>` wrapper types (you assert safety)

**Use these traits as bounds** to enforce safety in your own logging macros:

```rust
use redactable::slog::SlogRedacted;

// Macro that only accepts types certified as slog-safe
macro_rules! slog_safe {
    ($logger:expr, $msg:literal; $($key:literal => $value:expr),* $(,)?) => {{
        // The trait bound is enforced by this function call
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

For tracing:

```rust
use redactable::tracing::TracingRedacted;

macro_rules! trace_safe {
    ($($key:ident = $value:expr),* $(,)?) => {{
        fn assert_tracing_safe<T: TracingRedacted>(_: &T) {}
        $(assert_tracing_safe(&$value);)*
        tracing::info!($($key = tracing::field::debug(&$value)),*);
    }};
}
```

### Alternative: `SensitiveValue<T, P>` wrappers

If you want field-level protection even outside the logging integrations, use `SensitiveValue<T, P>` wrappers instead of `#[sensitive(P)]` attributes:

```rust
#[derive(Clone, Sensitive)]
struct User {
    email: SensitiveValue<String, Pii>,  // The value IS a wrapper, not a bare String
}

let user = User { email: SensitiveValue::from("alice@example.com".into()) };

// ✅ Safe: Debug shows the policy-redacted value, not the raw email
log::info!("Email: {:?}", user.email);

// ✅ Safe: explicit call for redacted form
log::info!("Email: {}", user.email.redacted());

// ⚠️ Intentional: .expose() for raw access (code review catches this)
let raw = user.email.expose();
```

### Trade-offs: attributes vs wrappers

| | `#[sensitive(P)]` | `SensitiveValue<T, P>` |
|---|---|---|
| **Ergonomics** | ✅ Work with actual types | ❌ Need `.expose()` everywhere |
| **Display (`{}`)** | Shows raw value | ✅ Not implemented (won't compile) |
| **Debug (`{:?}`)** | ✅ Shows `[REDACTED]`* | ✅ Shows policy-redacted value |
| **Serialization** | Shows raw value | Shows raw value |
| **slog/tracing safety** | ✅ Via container | ✅ Direct |

\* The `Sensitive` and `SensitiveDisplay` derives generate `Debug` impls that show `[REDACTED]`
  for sensitive data (disabled in test mode via `cfg(test)` or `feature = "testing"`).

⚠️ **Neither approach protects serialization.** Both serialize to raw values. This is intentional: serialization is used for API responses, database persistence, message queues, etc. If you need redacted serialization, call `.redact()` before serializing.

### Choosing an approach

- **Use the slog/tracing integrations** - Log containers via `&user` (slog) or `.tracing_redacted_valuable()` (tracing). Safety is automatic.
- **Use `SlogRedacted`/`TracingRedacted` bounds** - Enforce safety in your own helpers. Only certified types compile.
- **Use `SensitiveValue<T, P>` wrappers** - When you need field-level protection outside logging, or can't control the logging layer.
- **Use `#[sensitive(P)]` attributes** - Most ergonomic. Safe when logging containers through the integrations.

## Reference

### Trait map

**Domain layer** (what is sensitive):

| Trait | Purpose | Implemented By |
|---|---|---|
| `RedactableContainer` | Walkable containers | Structs/enums deriving `Sensitive`/`NotSensitive`/`NotSensitiveDisplay`, `NotSensitiveValue<T>`, standard leaves (passthrough), standard containers (`Option`, `Vec`, etc.) |
| `RedactableLeaf` | String-like leaves | `String`, `Cow<str>`, custom newtypes |

**Policy layer** (how to redact):

| Trait | Purpose | Implemented By |
|---|---|---|
| `RedactionPolicy` | Maps policy marker -> redaction | Built-in policies (`Secret`, `Token`, `Email`, etc.) and your custom policies |
| `TextRedactionPolicy` | Concrete string transformations | Built-ins (Full/Keep/Mask) |

**Application layer** (redaction machinery):

| Trait | Purpose | Implemented By |
|---|---|---|
| `PolicyApplicable` | Applies policy through wrappers | `String`, `Option`, `Vec`, etc. |
| `Redactable` | User-facing `.redact()` | Auto-implemented for `RedactableContainer` |
| `RedactableWithPolicy` | Policy-aware leaf redaction | `RedactableLeaf` types and external types |
| `ToRedactedOutput` | Logging output boundary | `RedactedOutput`, `RedactedJson`, `SensitiveValue<T,P>`, `RedactedOutputRef`, `RedactedJsonRef`, `NotSensitiveDisplay<T>`, `NotSensitiveDebug<T>`, `NotSensitiveJson<T>`, `RedactableDisplay` types |
| `RedactableMapper` | Internal traversal | `#[doc(hidden)]` |

**Types**:

| Type | Purpose |
|---|---|
| `RedactedOutput` | Enum for logging output: `Text(String)` or `Json(serde_json::Value)` |
| `RedactedJson` | Owned redacted JSON output (requires `json` feature) |
| `SensitiveValue<T, P>` | Wrapper that applies policy P to leaf type T |
| `NotSensitiveValue<T>` | Wrapper that passes T through unchanged |
| `NotSensitive<T>` | Wrapper for non-sensitive values that delegates to `T`'s formatting/slog impl (via `.not_sensitive()`) |
| `NotSensitiveDisplay<T>` | Wrapper using `Display` formatting at logging boundaries (via `.not_sensitive_display()`) |
| `NotSensitiveDebug<T>` | Wrapper using `Debug` formatting at logging boundaries (via `.not_sensitive_debug()`) |
| `NotSensitiveJson<T>` | Wrapper using JSON serialization at logging boundaries (via `.not_sensitive_json()`, requires `json` feature) |

**Display/logging layer**:

| Trait | Purpose | Implemented By |
|---|---|---|
| `RedactableDisplay` | Redacted string formatting | `SensitiveDisplay` derive, `NotSensitiveDisplay` derive, scalars (passthrough), containers (delegate to contents) |
| `SlogRedacted` | slog redaction safety marker | Derived types and safe slog wrappers |
| `TracingRedacted` | tracing redaction safety marker | Derived types and safe tracing wrappers |
| `SlogRedactedExt` | slog structured JSON logging | Types implementing `Redactable + Debug + Serialize` |
| `TracingRedactedExt` | tracing display string logging | Types implementing `ToRedactedOutput` |
| `TracingValuableExt` | tracing structured logging via `valuable` | Types implementing `Redactable + Clone + Valuable` |

### Supported types

**Leaves** (implement `RedactableLeaf`):
- `String`, `Cow<'_, str>`
- Custom newtypes (implement `RedactableLeaf` yourself)
- Note: `&str` is **not** supported for `Sensitive`; use owned strings or `Cow`

**Scalars** (with `#[sensitive(Secret)]`):
- Integers → `0`, floats → `0.0`, `bool` → `false`, `char` → `'*'`

**Scalars** (implement `RedactableDisplay` as passthrough):
- `String`, `str`, `bool`, `char`, integers, floats, `Cow<str>`, `PhantomData`, `()`
- NonZero integers: `NonZeroI8`/`I16`/`I32`/`I64`/`I128`/`Isize`, `NonZeroU8`/`U16`/`U32`/`U64`/`U128`/`Usize`
- std::time: `Duration`, `Instant`, `SystemTime`
- `std::cmp::Ordering`
- Feature-gated: `chrono` types (including `Duration`, `Month`, `Weekday`), `time` types (including `Duration`, `UtcOffset`, `Month`, `Weekday`), `Uuid`

**Containers** (implement `RedactableContainer` and `RedactableDisplay`):
- `Option<T>`, `Vec<T>`, `VecDeque<T>`, `Box<T>`, `Arc<T>`, `Rc<T>`, `Result<T, E>`, slices `[T]`
- `HashMap`, `BTreeMap`, `HashSet`, `BTreeSet`
- `Cell<T>`, `RefCell<T>`
- For `Sensitive`: walked automatically; policy annotations apply through them
- For `SensitiveDisplay`: formatted via `RedactableDisplay`, delegating to inner types
- Map keys are formatted with `Debug` and are not redacted

**Opaque types** (feature-gated):
- `serde_json::Value` (requires `json` feature): treated as a leaf that fully redacts to `Value::String("[REDACTED]")`. This is safe-by-default - unannotated `Value` fields are fully redacted because the dynamic structure could contain anything sensitive.

**External types**: `NotSensitiveValue<T>` for passthrough, `SensitiveValue<T, Policy>` with `RedactableWithPolicy` for redaction.

### Precedence and edge cases

**`#[sensitive(Policy)]` on strings** works with `String` and `Cow<str>` (and their wrappers like `Option<String>`). Scalars can only use `#[sensitive(Secret)]`. For custom types, use the `SensitiveValue<T, Policy>` wrapper instead.

**A type can implement both `RedactableLeaf` and derive `Sensitive`**. This is useful when you want the option to either traverse the type's containers or redact it as a unit depending on context. Which trait is used depends on how the value is declared:
- Bare type (unannotated): uses `RedactableContainer`, containers are traversed
- `SensitiveValue<T, Policy>` wrapper: uses `RedactableLeaf`, redacted as a unit

**Unannotated containers whose type derives `Sensitive` are still walked**. If a nested type has `#[sensitive(Policy)]` annotations on its leaves, those are applied even when the outer container is unannotated.

**Implementing `RedactableLeaf` on a struct or enum makes it a terminal value**. Its fields will not be traversed or individually redacted. This is useful when you want to redact the entire value as a unit, but nested `#[sensitive(Policy)]` annotations inside that type are ignored when it's used as a leaf.

**Sets can collapse after redaction**. `HashSet`/`BTreeSet` are redacted element-by-element and then collected back into a set. If redaction makes elements equal (e.g., multiple values redact to `"[REDACTED]"`), the resulting set may shrink. If cardinality matters, prefer a `Vec`.

### Built-in policies

| Policy | Use for | Example output |
|---|---|---|
| `Secret` | Scalars or generic redaction | `0` / `false` / `'*'` / `[REDACTED]` |
| `Token` | API keys | `...f456` (last 4) |
| `Email` | Email addresses | `al***@example.com` |
| `CreditCard` | Card numbers | `...1234` (last 4) |
| `Pii` | Generic PII (names, addresses) | `...oe` (last 2) |
| `PhoneNumber` | Phone numbers | `...4567` (last 4) |
| `IpAddress` | IP addresses | `....100` (last 4) |
| `BlockchainAddress` | Wallet addresses | `...abcdef` (last 6) |

### Custom policies

```rust
use redactable::{RedactionPolicy, TextRedactionPolicy};

#[derive(Clone, Copy)]
struct InternalId;

impl RedactionPolicy for InternalId {
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(2)
    }
}
```

## License

Licensed under the MIT license ([LICENSE.md](LICENSE.md) or [opensource.org/licenses/MIT](https://opensource.org/licenses/MIT)).
