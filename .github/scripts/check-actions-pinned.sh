#!/usr/bin/env bash
set -euo pipefail

# Composite actions can also carry `uses:`, so scan them when present.
scan_dirs=(.github/workflows)
[[ -d .github/actions ]] && scan_dirs+=(.github/actions)

failed=0
while IFS= read -r match; do
  location=${match%%:*}
  rest=${match#*:}
  line_number=${rest%%:*}
  line=${rest#*:}

  # Extract the action reference by anchoring on the actual `uses` KEY, not the
  # first textual "uses" on the line: a step name or an earlier value could
  # contain the word "uses". The key is `uses`, optionally quoted, in block /
  # inline / flow / quoted-key form; the captured value token runs until the next
  # space, comma, brace, or quote.
  #
  # This remains a LEXICAL guard for the maintainer's own workflows (catch an
  # accidental mutable tag), not a YAML parser. A `uses:` embedded inside a quoted
  # string value can still fool it -- but writing that requires control of the
  # workflow files, at which point CI is already lost. For true YAML-parse
  # robustness use a dedicated Actions linter (e.g. zizmor).
  if [[ $line =~ (^|[[:space:]]|[{,])[\"\']?uses[\"\']?[[:space:]]*:[[:space:]]*[\"\']?([A-Za-z0-9._/@-]+) ]]; then
    action=${BASH_REMATCH[2]}
  else
    # grep matched a uses-key line but the value did not parse: fail closed.
    echo "$location:$line_number: could not parse an action reference for a uses: key" >&2
    failed=1
    continue
  fi

  if [[ $action == ./* ]]; then
    continue
  fi

  ref=${action##*@}
  if [[ ! $ref =~ ^[0-9a-f]{40}$ ]] || [[ $line != *"#"* ]]; then
    echo "$location:$line_number: third-party action must use a 40-hex commit and a reviewable version comment: $action" >&2
    failed=1
  fi
# `uses:` is a key, and YAML admits it in block form (`uses: x@sha`), as an inline
# list item (`- uses: x@sha`), in flow style (`- { uses: x@sha }`), and with a
# quoted key (`"uses": x@sha`). All are valid and all must be caught. This is a
# LEXICAL guard, not a YAML parser, so it cannot cover every possible expression
# a determined author could write -- a dedicated Actions linter (e.g. zizmor) is
# the durable check. The mutant tests pin every form this guard is expected to
# reject; extend them alongside any regex change.
done < <(grep -RInE "(^|[[:space:]]|[{,])[\"']?uses[\"']?[[:space:]]*:[[:space:]]+" "${scan_dirs[@]}")

exit "$failed"
