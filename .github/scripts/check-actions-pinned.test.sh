#!/usr/bin/env bash
# Mutant tests for check-actions-pinned.sh.
#
# The guard exists to reject mutable third-party action references. A guard with
# no test of its own silently rots: an earlier revision matched only the block
# form `uses:` at line start and let the equally idiomatic inline list-item form
# `- uses: action@tag` through without a word.
set -uo pipefail

checker="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-actions-pinned.sh"
failures=0

# Runs the checker against a throwaway repo containing $2 as a workflow (or, when
# $3 is given, at that path) and asserts its exit status is $1.
expect() {
    local want="$1" name="$2" content="$3" path="${4:-.github/workflows/w.yml}"
    local dir
    dir="$(mktemp -d)"
    mkdir -p "$dir/$(dirname "$path")"
    printf '%s\n' "$content" > "$dir/$path"

    local got
    ( cd "$dir" && "$checker" ) >/dev/null 2>&1
    got=$?
    rm -rf "$dir"

    if [[ "$got" != "$want" ]]; then
        echo "FAIL: $name (want exit $want, got $got)" >&2
        failures=1
    else
        echo "ok: $name"
    fi
}

pinned='34e114876b0b11c390a56381ad16ebd13914f8d5'

# Accepted: a 40-hex commit with a reviewable version comment, in either form.
expect 0 "block form, pinned + comment"  "      - name: x
        uses: actions/checkout@${pinned} # v4"
expect 0 "inline form, pinned + comment" "      - uses: actions/checkout@${pinned} # v4"
expect 0 "local action is exempt"        "      - uses: ./.github/actions/local"

# Rejected: mutable refs. The inline case is the regression this test pins.
expect 1 "block form, mutable tag"       "      - name: x
        uses: actions/checkout@v4"
expect 1 "inline form, mutable tag"      "      - uses: actions/checkout@v4"
expect 1 "inline form, mutable branch"   "      - uses: dtolnay/rust-toolchain@master"

# Flow style is valid YAML and previously slipped past the guard entirely.
expect 1 "flow style, mutable tag"       "      - { uses: actions/checkout@v4 }"
expect 0 "flow style, pinned + comment"  "      - { uses: actions/checkout@${pinned} } # v4"

# Rejected: a bare SHA with no comment is unreviewable.
expect 1 "pinned but no comment"         "      - uses: actions/checkout@${pinned}"

# Quoted keys are valid YAML and previously slipped past the guard.
expect 1 "quoted key, mutable tag"       "      - { \"uses\": actions/checkout@v4 }"
expect 0 "quoted key, pinned + comment"  "      - { \"uses\": actions/checkout@${pinned} } # v4"
expect 1 "quoted key+value, mutable"     "      - { \"uses\": \"actions/checkout@v4\" }"

# A word containing "uses" earlier on the line must not be mistaken for the key
# (the extractor anchors on the real `uses:` key, not the first "uses" text).
expect 1 "decoy uses-word, real key mutable" "      - { \"uses-helper\": ok, uses: actions/checkout@v4 }"
expect 0 "decoy uses-word, real key pinned"  "      - { \"uses-helper\": ok, uses: actions/checkout@${pinned} } # v4"

# Composite actions carry `uses:` too and must not escape the scan.
expect 1 "composite action, mutable tag" "runs:
  using: composite
  steps:
    - uses: actions/checkout@v4" ".github/actions/c/action.yml"

if [[ "$failures" -ne 0 ]]; then
    echo "check-actions-pinned.sh mutant tests FAILED" >&2
    exit 1
fi
echo "all check-actions-pinned.sh mutant tests passed"
