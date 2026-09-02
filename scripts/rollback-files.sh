#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 [options] [commit-ish] [file ...]

Restore files to the versions in [commit-ish]. If no commit-ish provided,
defaults to HEAD~1. If file list omitted, the script restores all files
that changed between <commit-ish>..HEAD.

Options:
  --dry-run     Show which files would be restored (no changes)
  --force       Allow restore with uncommitted changes in working tree
  --no-push     Do not push the revert commit to origin
  -h|--help     Show this help

Examples:
  $0 HEAD~1                        # restore files changed in last commit
  $0 origin/main src/foo.ts         # restore src/foo.ts to origin/main version
  $0 --dry-run HEAD~2              # show files changed between HEAD~2..HEAD

EOF
}

DRY_RUN=0
FORCE=0
PUSH=1

if [ "$#" -eq 0 ]; then
  # empty, will use defaults below
  :
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --force) FORCE=1; shift ;;
    --no-push) PUSH=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) break ;;
  esac
done

COMMIT=${1:-HEAD~1}
if [ "$1" != "$COMMIT" ]; then
  shift || true
else
  # if commit provided as first non-option, consume it
  if [ "$#" -gt 0 ]; then
    if [[ ! "$1" =~ ^[A-Za-z0-9._/-]+$ ]]; then
      # unlikely, but fallback
      :
    else
      COMMIT=$1
      shift || true
    fi
  fi
fi

FILES=()
if [ $# -gt 0 ]; then
  # remaining args are explicit file paths
  while [[ $# -gt 0 ]]; do
    FILES+=("$1")
    shift
  done
else
  # detect changed files between commit and HEAD
  mapfile -t FILES < <(git diff --name-only "$COMMIT"..HEAD)
fi

if [ ${#FILES[@]} -eq 0 ]; then
  echo "No files to restore between $COMMIT and HEAD." >&2
  exit 0
fi

# Ensure we're in a git repo
if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "Not a git repository." >&2
  exit 2
fi

if [ $FORCE -ne 1 ]; then
  # require clean working tree
  if [ -n "$(git status --porcelain)" ]; then
    echo "Working tree is not clean. Commit/stash changes or rerun with --force." >&2
    git status --porcelain
    exit 3
  fi
fi

echo "Files to restore (${#FILES[@]}):"
for f in "${FILES[@]}"; do echo "  $f"; done

if [ $DRY_RUN -eq 1 ]; then
  echo "Dry run: no changes made."; exit 0
fi

echo "Restoring files from commit: $COMMIT"
git checkout "$COMMIT" -- "${FILES[@]}"

# Create a revert commit
git add "${FILES[@]}"
git commit -m "revert: restore files to $COMMIT"

if [ $PUSH -eq 1 ]; then
  echo "Pushing revert commit to origin..."
  git push origin HEAD
else
  echo "Skipped push (use --no-push to prevent pushing).";
fi

echo "Done. Restored ${#FILES[@]} file(s) to $COMMIT." 
