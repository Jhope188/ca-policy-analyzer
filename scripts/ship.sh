#!/usr/bin/env zsh
# Ship the current branch: validate locally, push, open a PR against main,
# and enable auto-merge (the PR merges itself the moment "PR Checks" passes
# on GitHub - no separate manual merge click needed).
#
# This exists because main auto-deploys to prod on every push (see
# .github/workflows/deploy-pages.yml). Every change must go through a branch
# + PR + green CI before it reaches main. This script is the one command that
# enforces that instead of relying on remembering the steps.
#
# Usage:
#   scripts/ship.sh "PR title here"
#
# Prerequisites:
#   - You're on a feature/fix branch (not main)
#   - Changes are committed
#   - You have already clicked around npm run dev in the browser and
#     confirmed the change behaves correctly - this script does NOT do that
#     for you, it only runs automated checks.
#   - gh CLI is authenticated (gh auth status)

set -euo pipefail

BRANCH="$(git rev-parse --abbrev-ref HEAD)"

if [[ "$BRANCH" == "main" ]]; then
  echo "❌ You're on main. Create a branch first:"
  echo "   git checkout -b fix/short-description"
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "❌ You have uncommitted changes. Commit them first."
  git status --short
  exit 1
fi

TITLE="${1:-}"
if [[ -z "$TITLE" ]]; then
  echo "❌ Usage: scripts/ship.sh \"PR title\""
  exit 1
fi

echo "── 1/4 Type-checking ──────────────────────────────────────"
npx tsc --noEmit

echo "── 2/4 Self-check scripts ─────────────────────────────────"
npm run check

echo "── (lint is informational only - main has pre-existing findings, not a gate) ──"
npm run lint || true

echo "── 3/4 Production build (GITHUB_PAGES=true) ──────────────"
GITHUB_PAGES=true npm run build

echo "── 4/4 Push branch + open PR + enable auto-merge ─────────"
git push -u origin "$BRANCH"

if gh pr view "$BRANCH" >/dev/null 2>&1; then
  echo "PR already exists for $BRANCH, skipping creation."
else
  gh pr create --base main --head "$BRANCH" --title "$TITLE" --fill
fi

gh pr merge "$BRANCH" --auto --squash

echo ""
echo "✅ Pushed, PR opened, auto-merge armed."
echo "   It merges automatically once 'PR Checks' passes on GitHub."
echo "   Watch it: gh pr checks $BRANCH --watch"
