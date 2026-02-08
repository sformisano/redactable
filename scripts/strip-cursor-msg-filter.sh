#!/usr/bin/env sh
# Used by strip-cursor-attribution.sh via git filter-branch --msg-filter.
# Reads commit message from stdin; writes it to stdout with any
# "Co-authored-by: Cursor <...>" / cursoragent lines removed.
while IFS= read -r line; do
  case "$line" in
    Co-authored-by:*[Cc]ursor*) ;;
    Co-authored-by:*cursoragent*) ;;
    *) printf '%s\n' "$line" ;;
  esac
done
