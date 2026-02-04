# Redactable

`redactable` is a redaction library for Rust. It lets you mark sensitive data in your
structs and enums and produce a safe, redacted version of the same type.
Logging and telemetry
are the most common use cases, but redaction is not tied to any logging framework.

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
  - [Wrapper types for foreign types](#wrapper-types-for-foreign-types)
- [Outputs (structured vs logging)](#outputs-structured-vs-logging)
- [Sensitive vs SensitiveDisplay](#sensitive-vs-sensitivedisplay)
  - [Sensitive (structured redaction)](#sensitive-structured-redaction)
  - [SensitiveDisplay (string formatting)](#sensitivedisplay-string-formatting)
- [SensitiveDisplay in depth](#sensitivedisplay-in-depth)
  - [Template syntax](#template-syntax)
  - [Field annotations](#field-annotations)
- [Decision guide](#decision-guide)
- [Logging output (explicit boundary)](#logging-output-explicit-boundary)
- [Integrations](#integrations)
  - [slog](#slog)
  - [tracing](#tracing)
- [Logging with maximum security](#logging-with-maximum-security)
  - [The logging footgun](#the-logging-footgun)
  - [Option A: Enforce `ToRedactedOutput` at the logging boundary](#option-a-enforce-toredactedoutput-at-the-logging-boundary-recommended)
  - [Option B: Use `SensitiveValue<T, P>` wrappers for sensitive leaves](#option-b-use-sensitivevaluet-p-wrappers-for-sensitive-leaves)
  - [Trade-offs: attributes vs wrappers](#trade-offs-attributes-vs-wrappers)
  - [Practical wrappers for slog and tracing](#practical-wrappers-for-slog-and-tracing)
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
- **Consistent annotation workflow**: both `Sensitive` and `SensitiveDisplay` follow the same pattern—unannotated scalars pass through, unannotated containers are handled via their trait, and `#[sensitive(Policy)]` applies redaction.
- **Types are preserved**: `Sensitive`'s `.redact()` returns the same type, not a string or wrapper.

## How it works

The `Sensitive` derive macro generates traversal code. For each field, it calls `RedactableContainer::redact_with`. This uniform interface is what makes everything compose.

| Field kind | What happens |
|------------|--------------|
| **Containers** (structs/enums deriving `Sensitive`) | Traversal walks into them recursively, visiting each field |
| **Unannotated leaves** (String, primitives, etc.) | These implement `RedactableContainer` as a passthrough - they return themselves unchanged |
| **Annotated leaves** (`#[sensitive(Policy)]`) | The macro generates transformation code that applies the policy, bypassing the normal `RedactableContainer::redact_with` call |

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
- `#[sensitive(Default)]` on an `Option<String>` leaf applies the policy to the string inside

```rust
#[derive(Clone, Sensitive)]
struct Inner {
    #[sensitive(Default)]
    secret: String,
}

#[derive(Clone, Sensitive)]
struct Outer {
    maybe_string: Option<String>,  // Option walks, inner String is passthrough → unchanged
    maybe_inner: Option<Inner>,    // Option walks, inner Inner is walked → secret redacted
    #[sensitive(Default)]
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

- `#[sensitive(Default)]` on scalars: replaces the value with a default (0, false, `'*'`)
- `#[sensitive(Default)]` on strings: replaces with `"[REDACTED]"`
- `#[sensitive(Policy)]` on strings: applies the policy's redaction rules

```rust
#[derive(Clone, Sensitive)]
struct Login {
    username: String,           // unchanged
    #[sensitive(Default)]
    password: String,           // redacted to "[REDACTED]"
    #[sensitive(Default)]
    attempts: u32,              // redacted to 0
}
```

#### ⚠️ Qualified primitive paths don't work with `#[sensitive(Default)]`

The derive macro decides how to handle `#[sensitive(Default)]` based on a **syntactic check** of how you wrote the type. Only bare primitive names like `u32`, `bool`, `char` are recognized as scalars. Qualified paths like `std::primitive::u32` are not.

This matters because:

- **Unannotated leaves**: Both `u32` and `std::primitive::u32` work identically (passthrough via `RedactableContainer`)
- **`#[sensitive(Default)]` leaves**:
  - `u32` → recognized as scalar → redacts to `0` ✅
  - `std::primitive::u32` → not recognized → tries to use `PolicyApplicable` → **compile error** ❌

```rust
#[derive(Clone, Sensitive)]
struct Example {
    #[sensitive(Default)]
    count: u32,                    // ✅ works: recognized as scalar, redacts to 0

    #[sensitive(Default)]
    other: std::primitive::u32,    // ❌ compile error: u32 doesn't implement PolicyApplicable
}
```

**Workaround**: Always use bare primitive names (`u32`, `bool`, etc.) when applying `#[sensitive(Default)]`.

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

Some types you own need to satisfy `Redactable` bounds but have no sensitive data. Use `#[derive(NotSensitive)]` to generate a no-op `RedactableContainer` impl:

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

## Outputs (structured vs logging)

- **Structured redaction** (`Redactable` trait, `.redact()` method): returns the same type with sensitive leaves redacted
- **Logging output** (`ToRedactedOutput` trait, `RedactedOutput` enum): converts to a safe-to-log representation
- **Structured logging adapters**: see [Integrations](#integrations) for slog and tracing

The `RedactedOutput` enum represents safe-to-log output:

```rust
use redactable::{RedactedOutput, ToRedactedOutput};

let output: RedactedOutput = sensitive_value.to_redacted_output();
match output {
    RedactedOutput::Text(s) => /* Debug-like string */,
    #[cfg(feature = "json")]
    RedactedOutput::Json(v) => /* serde_json::Value - works with slog::Serde */,
}
```

⚠️ **The Json variant uses `serde_json::Value`**, which integrates well with slog's structured logging. For tracing, the Json variant is converted to a string since tracing's `Value` trait is sealed.

## Sensitive vs SensitiveDisplay

There are two derive macros for redaction. Pick the one that matches your constraints:

| | `Sensitive` | `SensitiveDisplay` |
|---|---|---|
| **Output** | Same type with redacted leaves | Redacted string |
| **Requires `Clone`** | Yes | No |
| **Traverses containers** | Yes (walks all fields) | No (only template placeholders) |
| **Unannotated scalars** | Passthrough | Passthrough |
| **Unannotated containers** | Walked via `RedactableContainer` | Formatted via `RedactableDisplay` |
| **Best for** | Structured data | Display strings, non-Clone types |

### Sensitive (structured redaction)

Use `Sensitive` when you can guarantee `Clone`. Nested containers are traversed automatically; leaves are only redacted when annotated with `#[sensitive(Policy)]`.

```rust
use redactable::Sensitive;

#[derive(Clone, Sensitive)]
struct LoginAttempt {
    user: String,                // unchanged (no annotation)
    #[sensitive(Default)]
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
        #[sensitive(Default)]       // redacted to "[REDACTED]"
        password: String,
    },
}

let err = LoginError::Invalid {
    user: "alice".into(),
    password: "hunter2".into(),
};
// err.redacted_display() → "login failed for alice [REDACTED]"
```

See [SensitiveDisplay in depth](#sensitivedisplay-in-depth) for template syntax and field annotations.

Nested `SensitiveDisplay` types are redacted automatically without extra annotations:

```rust
use redactable::{Default as RedactableDefault, SensitiveDisplay};

#[derive(SensitiveDisplay)]
enum InnerError {
    #[error("db password {password}")]
    BadPassword {
        #[sensitive(RedactableDefault)]
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
| `#[not_sensitive]` | Renders with raw `Display` (or `Debug` if `{:?}`) — use for types without `RedactableDisplay` |
| `#[sensitive(Default)]` | Scalars → default value; strings → `"[REDACTED]"` |
| `#[sensitive(Policy)]` | Applies the policy's redaction rules |

This matches `Sensitive` behavior: scalars pass through, nested containers use their redaction trait.

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

| Situation | Use |
|---|---|
| Structured data with `Clone` | `#[derive(Sensitive)]` |
| Types without `Clone` | `#[derive(SensitiveDisplay)]` |
| Type with no sensitive data | `#[derive(NotSensitive)]` |

**Error types** are a common case: use `Sensitive` if your error type implements `Clone`, otherwise use `SensitiveDisplay`.

**How to handle foreign types?**

| Situation | Use |
|---|---|
| Foreign type, no sensitive data | `NotSensitiveValue<T>` wrapper |
| Foreign type, needs redaction | `SensitiveValue<T, Policy>` + `RedactableWithPolicy` |

**How to produce logging output?**

| Situation | Use |
|---|---|
| Container → redacted text | `.redacted_output()` |
| Container → redacted JSON | `.redacted_json()` (requires `json` feature) |
| Non-sensitive value | `.not_sensitive()` / `.not_sensitive_debug()` / `.not_sensitive_json()` |
| SensitiveDisplay type | `.redacted_display()` or `.to_redacted_output()` |

## Logging output (explicit boundary)

`ToRedactedOutput` is the single logging-safe bound. It produces a `RedactedOutput`:

- `RedactedOutput::Text(String)`
- `RedactedOutput::Json(serde_json::Value)` (requires the `json` feature)

Several wrappers produce `RedactedOutput`:

- `SensitiveValue<T, Policy>` (Text)
- `RedactedOutputRef` / `.redacted_output()` (Text)
- `RedactedJsonRef` / `.redacted_json()` (Json, `json` feature)
- `NotSensitiveDisplay` / `.not_sensitive()` (Text)
- `NotSensitiveDebug` / `.not_sensitive_debug()` (Text)
- `NotSensitiveJson` / `.not_sensitive_json()` (Json, `json` feature)

```rust
use redactable::{
    NotSensitiveDebugExt, NotSensitiveExt, NotSensitiveJsonExt, RedactedJsonExt, RedactedOutput,
    RedactedOutputExt, RedactableLeaf, SensitiveValue, Sensitive, Default, ToRedactedOutput,
};

#[derive(Clone)]
struct ExternalId(String);

impl RedactableLeaf for ExternalId {
    fn as_str(&self) -> &str { self.0.as_str() }
    fn from_redacted(redacted: String) -> Self { Self(redacted) }
}

#[derive(Clone, Sensitive)]
struct Event {
    id: SensitiveValue<ExternalId, Default>,
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
log_redacted(&event.status.not_sensitive());
log_redacted(&event.status.not_sensitive_debug());
#[cfg(feature = "json")]
log_redacted(&event.status.not_sensitive_json());
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
redactable = { version = "0.1", features = ["slog"] }
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

Both work because they implement `slog::Value` - containers via the derive macro, wrappers via a manual implementation. No explicit conversion needed.

### tracing

For structured logging with tracing, use the `valuable` integration:

```toml
[dependencies]
redactable = { version = "0.1", features = ["tracing-valuable"] }
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

## Logging with maximum security

For high-security domains (finance, healthcare, compliance-sensitive systems), you need guarantees that sensitive data can't be accidentally logged. This section covers two approaches to achieve that.

### The logging footgun

With `#[sensitive(P)]` attributes, the value is still the bare type at runtime:

```rust
#[derive(Clone, Sensitive)]
struct User {
    #[sensitive(Pii)]
    email: String,  // At runtime, this is just a String
}

let user = User { email: "alice@example.com".into() };

// ❌ Nothing stops you from logging the value directly
log::info!("Email: {}", user.email);  // Logs "alice@example.com" unredacted!

// You must remember to redact the container first
let redacted = user.redact();
log::info!("Email: {}", redacted.email);  // Now it's "al***@example.com"
```

### Option A: Enforce `ToRedactedOutput` at the logging boundary (recommended)

The strongest approach is to make it **impossible to log raw types** by requiring `T: ToRedactedOutput` at the logging boundary:

```rust
use redactable::{RedactedOutput, ToRedactedOutput};

// This function ONLY accepts types that implement ToRedactedOutput
fn log_safe<T: ToRedactedOutput>(value: &T) {
    match value.to_redacted_output() {
        RedactedOutput::Text(text) => log::info!("{}", text),
        #[cfg(feature = "json")]
        RedactedOutput::Json(json) => log::info!("{}", json),
    }
}
```

Now the compiler enforces what you can pass:

```rust
// ✅ Containers: .redacted_output() redacts first, then produces safe output
log_safe(&user.redacted_output());

// ✅ SensitiveValue wrappers: they carry their policy and redact on output
log_safe(&api_token);  // where api_token: SensitiveValue<String, Token>

// ✅ Known non-sensitive values: explicitly mark them as safe to log
// Use this for values you KNOW are not sensitive (IDs, timestamps, status codes)
log_safe(&request_id.not_sensitive());
log_safe(&"Operation completed".not_sensitive());

// ❌ Raw types won't compile - forces you to make an explicit choice
log_safe(&user);        // ERROR: User doesn't implement ToRedactedOutput
log_safe(&user.email);  // ERROR: String doesn't implement ToRedactedOutput
```

**Why `.not_sensitive()` matters:** Raw `String` and primitives don't implement `ToRedactedOutput` because the compiler can't know if they're sensitive. By calling `.not_sensitive()`, you're explicitly declaring "I've reviewed this value and it's safe to log." This creates an audit trail in your code.

**To adopt this pattern:**
1. Create logging helpers that require `T: ToRedactedOutput`
2. Disallow direct use of `log::info!("{}", value)` for potentially sensitive data (via code review or lints)
3. All logging goes through your safe helpers

### Option B: Use `SensitiveValue<T, P>` wrappers for sensitive leaves

If you can't enforce trait bounds at the logging boundary, you can use `SensitiveValue<T, P>` wrappers instead of `#[sensitive(P)]` attributes:

```rust
#[derive(Clone, Sensitive)]
struct User {
    email: SensitiveValue<String, Pii>,  // The value IS a wrapper, not a bare String
}

let user = User { email: SensitiveValue::from("alice@example.com".into()) };

// ✅ Safe: Debug shows "[REDACTED]"
log::info!("Email: {:?}", user.email);

// ✅ Safe: explicit call for redacted form
log::info!("Email: {}", user.email.redacted());

// ⚠️ Intentional: .expose() for raw access (code review catches this)
log::info!("Email: {}", user.email.expose());
```

### Trade-offs: attributes vs wrappers

| | `#[sensitive(P)]` | `SensitiveValue<T, P>` |
|---|---|---|
| **Ergonomics** | ✅ Work with actual types | ❌ Need `.expose()` everywhere |
| **Display (`{}`)** | ❌ Shows raw value | ✅ Not implemented (won't compile) |
| **Debug (`{:?}`)** | ❌ Shows raw value | ✅ Shows `[REDACTED]` |
| **Serialization** | Shows raw value | Shows raw value |

⚠️ **Neither approach protects serialization.** Both `#[sensitive(P)]` and `SensitiveValue<T, P>` serialize to raw values. This is intentional: serialization is used for much more than logging (API responses, database persistence, message queues, caching, etc.). Automatic redaction during serialization would break these use cases. If you need redacted serialization, call `.redact()` before serializing, or build wrapper functions/traits that enforce this for your specific context.

### Practical wrappers for slog and tracing

You can enforce `ToRedactedOutput` at the logging boundary using macros (which enforce the bound by calling `.to_redacted_output()`).

**slog:**

```rust
macro_rules! slog_safe {
    ($logger:expr, $msg:literal; $key:literal => $value:expr) => {{
        let output: redactable::RedactedOutput = ($value).to_redacted_output();
        slog::info!($logger, $msg; $key => output.to_string());
    }};
}

slog_safe!(logger, "event"; "user" => user.redacted_output());  // ✅
slog_safe!(logger, "event"; "user" => user);                    // ❌ Won't compile
slog_safe!(logger, "event"; "email" => user.email);             // ❌ Won't compile
```

**tracing:**

```rust
macro_rules! trace_safe {
    ($field:literal = $value:expr) => {{
        // Calling .to_redacted_output() enforces the trait bound at compile time
        let output: redactable::RedactedOutput = ($value).to_redacted_output();
        tracing::info!({ $field } = %output);
    }};
}

trace_safe!("user" = user.redacted_output());      // ✅ Container via .redacted_output()
trace_safe!("token" = sensitive_token);            // ✅ SensitiveValue<T, P>
trace_safe!("id" = request_id.not_sensitive());    // ✅ Explicitly non-sensitive
trace_safe!("user" = user);                        // ❌ Won't compile - raw container
trace_safe!("email" = user.email);                 // ❌ Won't compile - raw String
```

💡 **Tip:** Combine these wrappers with code review rules or clippy lints that flag direct use of `tracing::info!` or `slog::info!` with potentially sensitive data.

**When to use which:**
- **Option A (`ToRedactedOutput` enforcement)** - Strongest guarantee. Use when you control the logging layer and can enforce the trait bound.
- **Option B (`SensitiveValue` wrappers)** - Field-level protection. Debug shows redacted, Display won't compile. Use when you can't control the logging layer.
- **`#[sensitive(P)]` attributes** - Most ergonomic. Use when your team logs containers (not individual values) and enforces this via code review.

## Reference

### Trait map

**Domain layer** (what is sensitive):

| Trait | Purpose | Implemented By |
|---|---|---|
| `RedactableContainer` | Walkable containers | Structs/enums deriving `Sensitive`, `NotSensitiveValue<T>` |
| `RedactableLeaf` | String-like leaves | `String`, `Cow<str>`, custom newtypes |

**Policy layer** (how to redact):

| Trait | Purpose | Implemented By |
|---|---|---|
| `RedactionPolicy` | Maps policy marker -> redaction | Your custom policies |
| `TextRedactionPolicy` | Concrete string transformations | Built-ins (Full/Keep/Mask) |

**Application layer** (redaction machinery):

| Trait | Purpose | Implemented By |
|---|---|---|
| `PolicyApplicable` | Applies policy through wrappers | `String`, `Option`, `Vec`, etc. |
| `Redactable` | User-facing `.redact()` | Auto-implemented for `RedactableContainer` |
| `RedactableWithPolicy` | Policy-aware leaf redaction | `RedactableLeaf` types and external types |
| `ToRedactedOutput` | Logging output boundary | `SensitiveValue<T,P>`, `RedactedOutputRef`, `RedactedJsonRef`, `NotSensitive*`, `RedactableDisplay` |
| `RedactableMapper` | Internal traversal | `#[doc(hidden)]` |

**Types**:

| Type | Purpose |
|---|---|
| `RedactedOutput` | Enum for logging output: `Text(String)` or `Json(serde_json::Value)` |
| `SensitiveValue<T, P>` | Wrapper that applies policy P to leaf type T |
| `NotSensitiveValue<T>` | Wrapper that passes T through unchanged |

**Display/logging layer**:

| Trait | Purpose | Implemented By |
|---|---|---|
| `RedactableDisplay` | Redacted string formatting | `SensitiveDisplay` derive, scalars (passthrough) |
| `SlogRedactedExt` | slog structured JSON logging | Types implementing `Redactable + Serialize` |
| `TracingRedactedExt` | tracing display string logging | Types implementing `ToRedactedOutput` |
| `TracingValuableExt` | tracing structured logging via `valuable` | Types implementing `Redactable + Valuable` |

Note: `SensitiveDisplay` also generates `slog::Value` when the `slog` feature is enabled, emitting the redacted display string.

### Supported types

**Leaves** (implement `RedactableLeaf`):
- `String`, `Cow<'_, str>`
- Custom newtypes (implement `RedactableLeaf` yourself)
- Note: `&str` is **not** supported for `Sensitive`; use owned strings or `Cow`

**Scalars** (with `#[sensitive(Default)]`):
- Integers → `0`, floats → `0.0`, `bool` → `false`, `char` → `'*'`

**Scalars** (implement `RedactableDisplay` as passthrough):
- `String`, `str`, `bool`, `char`, integers, floats, `Cow<str>`, `PhantomData`, `()`
- Feature-gated: `chrono` types, `time` types, `Uuid`

**Containers** (implement `RedactableContainer`):
- `Option<T>`, `Vec<T>`, `Box<T>`, `Arc<T>`, `Result<T, E>`
- `HashMap`, `BTreeMap`, `HashSet`, `BTreeSet`
- All walked automatically; policy annotations apply through them

**External types**: `NotSensitiveValue<T>` for passthrough, `SensitiveValue<T, Policy>` with `RedactableWithPolicy` for redaction.

### Precedence and edge cases

**`#[sensitive(Policy)]` on strings** works with `String` and `Cow<str>` (and their wrappers like `Option<String>`). Scalars can only use `#[sensitive(Default)]`. For custom types, use the `SensitiveValue<T, Policy>` wrapper instead.

**A type can implement both `RedactableLeaf` and derive `Sensitive`**. This is useful when you want the option to either traverse the type's containers or redact it as a unit depending on context. Which trait is used depends on how the value is declared:
- Bare type (unannotated): uses `RedactableContainer`, containers are traversed
- `SensitiveValue<T, Policy>` wrapper: uses `RedactableLeaf`, redacted as a unit

**Unannotated containers whose type derives `Sensitive` are still walked**. If a nested type has `#[sensitive(Policy)]` annotations on its leaves, those are applied even when the outer container is unannotated.

**Implementing `RedactableLeaf` on a struct or enum makes it a terminal value**. Its fields will not be traversed or individually redacted. This is useful when you want to redact the entire value as a unit, but nested `#[sensitive(Policy)]` annotations inside that type are ignored when it's used as a leaf.

**Sets can collapse after redaction**. `HashSet`/`BTreeSet` are redacted element-by-element and then collected back into a set. If redaction makes elements equal (e.g., multiple values redact to `"[REDACTED]"`), the resulting set may shrink. If cardinality matters, prefer a `Vec`.

### Built-in policies

| Policy | Use for | Example output |
|---|---|---|
| `Default` | Scalars or generic redaction | `0` / `false` / `'*'` / `[REDACTED]` |
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
