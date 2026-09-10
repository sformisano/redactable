# Contributing documentation

The [README](README.md) teaches how to use Redactable. The
[reference](docs/reference.md) holds detailed contracts, and the
[changelog](CHANGELOG.md) explains upgrades.

## Voice and structure

Use the [February 10 README](https://github.com/sformisano/redactable/blob/75dc1dd7f923c0ba93054f831c63dc8335026838/README.md)
as a reference for voice and teaching order. Its API behavior is historical;
check current source and tests for technical claims.

- Address the reader directly. Explain why a constraint exists before listing its traits.
- Introduce one idea, show a small example, then explain its consequence.
- Keep structured redaction and formatted redaction in parallel sections. Explain the combined derive after both.
- Update the paragraph that owns a changed behavior. Avoid appending another qualification elsewhere.
- Keep disclosure risks beside the affected example. Put detailed restrictions in the reference and old-name mappings in the changelog.
- Use tables for choices. Keep test infrastructure and verification reports out of the walkthrough.
- When moving content, give each current behavior a destination and check the links.

## Examples

Run the README's consumer doctests after changing runnable examples:

```sh
cargo test --locked --doc --manifest-path cargo-fixtures/readme-examples/Cargo.toml
```

Keep imports, dependencies, and expected output accurate. Use `compile_fail` for
rejected usage and `ignore` for incomplete sketches or examples needing an external runtime.
The ignored tracing and logging sketches need the relevant integration tests;
the README doctest command does not execute them.

Before submitting, read each changed section in order. Check that its heading
matches the question it answers, and that every moved contract remains reachable.
