#!/usr/bin/env bash
# Strip Cursor from git history so it never appears as a contributor:
# - Remove "Co-authored-by: Cursor <...>" from commit messages
# - Rewrite author/committer to REPO_IDENTITY when they are cursoragent/Cursor
# - Full rewrite so GitHub recomputes contributors (fixes stale cache)
# Run from repo root. Then: git push --force-with-lease origin main

set -e
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Not inside a git repo. Run from repo root." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILTER_SCRIPT="$SCRIPT_DIR/strip-cursor-msg-filter.sh"
if [[ ! -x "$FILTER_SCRIPT" ]]; then
  chmod +x "$FILTER_SCRIPT"
fi

BRANCH="${1:-main}"
REPO_NAME="$(git config user.name)"
REPO_EMAIL="$(git config user.email)"
if [[ -z "$REPO_EMAIL" || -z "$REPO_NAME" ]]; then
  echo "Set git user.name and user.email in this repo (or globally) so Cursor can be replaced." >&2
  exit 1
fi

# Rewrite author/committer when they are Cursor/cursoragent so GitHub drops them from contributors.
# Normalize GIT_COMMITTER_DATE to GIT_AUTHOR_DATE so every commit object changes (new SHAs) and
# GitHub is forced to recompute contributors from the new history.
export REPO_NAME REPO_EMAIL
ENV_FILTER='
  case "$GIT_AUTHOR_EMAIL" in *[Cc]ursor*|*cursoragent*) export GIT_AUTHOR_NAME="$REPO_NAME" GIT_AUTHOR_EMAIL="$REPO_EMAIL" ;; esac
  case "$GIT_AUTHOR_NAME" in *[Cc]ursor*) export GIT_AUTHOR_NAME="$REPO_NAME" GIT_AUTHOR_EMAIL="$REPO_EMAIL" ;; esac
  case "$GIT_COMMITTER_EMAIL" in *[Cc]ursor*|*cursoragent*) export GIT_COMMITTER_NAME="$REPO_NAME" GIT_COMMITTER_EMAIL="$REPO_EMAIL" ;; esac
  case "$GIT_COMMITTER_NAME" in *[Cc]ursor*) export GIT_COMMITTER_NAME="$REPO_NAME" GIT_COMMITTER_EMAIL="$REPO_EMAIL" ;; esac
  export GIT_COMMITTER_DATE="$GIT_AUTHOR_DATE"
'

echo "Rewriting branch: $BRANCH (strip Cursor from messages and author/committer; identity=$REPO_NAME <$REPO_EMAIL>)"
git filter-branch -f --msg-filter "$FILTER_SCRIPT" --env-filter "$ENV_FILTER" -- "$BRANCH"

echo ""
echo "Done. Verify: git log --format='%h %ae %an' -5"
echo "Then push (safe rewrite): git push --force-with-lease origin $BRANCH"
echo "GitHub will recompute contributors from the new history; cursoragent will disappear."
