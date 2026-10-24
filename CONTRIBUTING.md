# Contributing documentation

The [README](README.md) teaches how to use Redactable. The
[reference](docs/reference.md) holds detailed contracts, and the
[changelog](CHANGELOG.md) explains upgrades.

The [skill catalog](https://github.com/sformisano/redactable/blob/main/.skillcatalog/README.md) guides decisions about where to use
Redactable, disclosure, design tradeoffs, and review. Keep API syntax, exhaustive
feature lists, and step-by-step instructions in product documentation. Retain a
short example in a skill only when it clarifies a decision, and link to the
authoritative documentation for mechanics. Check claims against the current
implementation and the consumer's version.
The README's [disclosure decision](README.md#choose-what-diagnostics-retain)
owns the product guidance for useful context and protected fields.

## Voice and structure

Use the [February 10 README](https://github.com/sformisano/redactable/blob/75dc1dd7f923c0ba93054f831c63dc8335026838/README.md)
as a reference for voice and teaching order. Its API behavior is historical;
check current source and tests for technical claims.

- Address the reader directly. Explain why a constraint exists before listing its traits.
- Introduce one idea, show a small example, then explain its consequence.
- Keep structured redaction and formatted redaction in parallel sections. Explain the combined derive after both.
- Update the paragraph that owns a changed behavior. Avoid appending another qualification elsewhere.
- Keep disclosure risks beside the affected example. Put detailed restrictions in the reference and old-name mappings in the changelog.
- Keep ordinary counts and correlation fields useful. Give masking a concrete confidentiality reason in the example's domain.
- Use `Secret` for credential examples unless the example explicitly justifies partial disclosure.
- Show the structured adapter when logging fields matter. Identify whole-value placeholders as fallbacks with different output.
- Use tables for choices. Keep test infrastructure and verification reports out of the walkthrough.
- When moving content, give each current behavior a destination and check the links.

## Examples

Run the README's consumer doctests after changing runnable examples:

```sh
RUSTFLAGS="--cfg tracing_unstable" cargo test --locked --doc --manifest-path cargo-fixtures/readme-examples/Cargo.toml
RUSTFLAGS="--cfg tracing_unstable" cargo test --locked --doc --workspace --all-features
```

The consumer fixture enables `tracing-valuable`; its capture subscriber checks
actual tracing output, including the upstream interface enabled by `tracing_unstable`.
Keep imports, dependencies, and expected output accurate. Complete runnable
examples with setup and assertions. Use `compile_fail` for intentional rejection,
`text` for syntax fragments, and `no_run` only when execution requires external
resources. A `no_run` example still needs complete, compilable setup.
Separate successful examples from rejected calls so failures cannot pass for
unrelated missing names or dependencies. Source derive documentation links to
the consumer-tested public examples without adding a runtime dependency cycle.

Before submitting, read each changed section in order. Check that its heading
matches the question it answers, and that every moved contract remains reachable.
