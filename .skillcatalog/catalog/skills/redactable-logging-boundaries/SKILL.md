---
name: redactable-logging-boundaries
description: "Use when designing or changing a logging, tracing, telemetry, or diagnostic path that uses Redactable. Decide where conversion occurs, which representation reaches the sink, and how to verify disclosure and runtime costs."
metadata:
  skillcatalog/display_name: "Redactable Logging Boundaries"
  skillcatalog/author: "Salvatore Formisano"
  skillcatalog/created_at: "2026-04-29T15:18:46Z"
  skillcatalog/updated_at: "2026-11-27T23:30:11Z"
---
# Redactable Logging Boundaries

For Redactable 0.17, trace the value from its source to the actual output writer.
Apply a redacted operation or reviewed adapter before sensitive data reaches
that writer, including error reports and ad hoc diagnostics.

## Make the boundary explicit

Use Redactable's checked level macros to require a declared policy for fields
and message arguments. A plain field selects the producer's JSON. An explicit format
argument inserts the producer's declared text. Applications can use their
installed `log` logger or select slog or tracing once with `logging::set_sink`.
For a custom output pipeline, accept `ToRedacted` at the boundary and pass the
resulting `RedactedValue` to the writer. Review public declarations and bypasses
against the intended audience.
Retain the operation's useful identity, query, transition and outcome context.
A projection that replaces an entire request or result with a mask can satisfy
the trait while preventing diagnosis. Generic envelopes can delegate query
filters, operation identifiers and results to their own field policies. A map
key is retained as a whole and its type must be declared public.

Do not serialize or interpolate sensitive data into a string before conversion.
Neither a bypass wrapper nor the low-level free `redact(value)` function repairs
that string. Review ordinary error `Display`, error chains, debug dumps,
inherited slog context, and subscriber-added fields at their source. If a
native bridge such as `tracing/log-always` forwards events, inspect the output
of each destination that needs the same disclosure and field shape.

## Choose the output the sink actually needs

- Use a structured producer when downstream tools need fields, and a display
  producer when a selected message is sufficient. A text accessor rendering
  compact JSON is still text to the sink. A text-only producer's `json()` is
  an object with a `message` field; it is not a scalar string. Assert the actual
  representation when composing nested projections.
- In a checked macro, use a plain field for the producer's JSON. Both `:%`
  and `:?` select the producer's declared text. A format-specific bypass
  deliberately exposes the wrapped Display, Debug, or JSON representation.
- For nested objects and arrays, configure a `log` backend that serializes
  key-value fields or a slog drain with nested-value support. An existing
  native `log` or slog call can use its named JSON adapter. Native slog emits
  a whole-value placeholder for a borrowed `Sensitive` or `SensitiveDual`
  source. Check that useful fields survive in the drain's output.
- A checked tracing plain field carries compact JSON text on stable tracing.
  For nested output, enable `tracing-valuable`, build with
  `--cfg tracing_unstable`, and exercise a Valuable-aware subscriber. Existing
  native tracing calls can select their display, redacted `Debug`, or
  typed `Valuable` adapter.
- `Sensitive` masks annotated fields in generated `Debug` and delegates other
  fields to their own `Debug`. `SensitiveDisplay` and `SensitiveDual` render
  policy-shaped templates. For an opaque JSON payload, check the structural
  field's explicit decision. Use a typed diagnostic view to retain selected
  metadata from a payload that also contains credentials.

## Bound cost and failure behavior

Structural producers clone before redacting. Consider large payloads, shared
ownership, and live `RefCell` borrows before putting them on frequent or critical
paths. Borrowed display formatting has different behavior; a consuming adapter
can avoid the outer clone but not every clone during nested traversal.

Retain a `RedactedValue` when several sinks need the same snapshot. Pass it
by reference to a checked macro or to Serde to reuse the stored JSON.
Checked text fields borrow stored text or render compact JSON when the value
has only JSON. Queued slog drains can request an owned copy. Borrowed formatting and the native slog text adapter can run again on
emission. The native typed `Valuable` adapter can expose interior-mutable
redacted objects, so later traversal can observe caller-driven mutation.

Serialization errors replace the whole JSON output with a placeholder. Policies,
clones, formatters, and serializers can still panic. Do not turn a logging
failure into raw fallback output, and do not promise panic isolation.

Use `RedactedList` when item count needs a limit, but assess its visible omitted
count. It does not bound bytes, depth, allocations, or per-item policy work.
Set any additional resource limits at the application boundary. Output limits
control size and relevance separately from confidentiality; label omissions
and counts accordingly instead of calling all omitted content secret.

## Verify the emitted result

Capture the actual logger or subscriber output using synthetic sensitive values.
Assert both the expected useful fields and the absence of forbidden raw values.
Include realistic public context alongside protected values in the same record.
Check nested and before/after projections, error and fallback paths, and unchanged
business values and raw serialization where supported. Shape-only assertions or
the presence of a mask cannot establish useful, correctly protected output.

## Mechanics

- [Checked logging and backend selection](https://github.com/sformisano/redactable/blob/main/README.md#checked-logging)
- [Runnable JSON logger example](https://github.com/sformisano/redactable/blob/main/README.md#log)
- [Output, timing, failure, and adapter contracts](https://github.com/sformisano/redactable/blob/main/docs/reference.md#output-and-adapter-contracts)
- [Collection output](https://github.com/sformisano/redactable/blob/main/docs/reference.md#bounded-list-output)
- [Testing redacted output](https://github.com/sformisano/redactable/blob/main/docs/reference.md#testing-redacted-output)
