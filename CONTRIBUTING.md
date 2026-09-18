# Contributing / shipping workflow

`main` auto-deploys to GitHub Pages (prod) on every push
([.github/workflows/deploy-pages.yml](.github/workflows/deploy-pages.yml)).
There is no manual "are you sure" step after that — so **nothing goes
directly to `main`**. Every change follows this flow:

## 1. Branch

```
git checkout -b fix/short-description
```

(`fix/…`, `feat/…`, `docs/…` — doesn't matter much, just not `main`.)

## 2. Make the change, then verify it in the browser

```
npm run dev
```

Actually click through the affected flow (Templates tab, Findings tab, the
specific policy/check you touched, etc.). **Passing `tsc` or a production
build does not prove the feature works** — several past regressions in this
project (unsupported Graph `$filter`, a page-size/timeout interaction, a
token-acquisition race from parallelizing scans) compiled and built cleanly
but were completely broken at runtime. The browser check is what catches
those.

## 3. Run the full local check suite

```
npx tsc --noEmit
npm run check                      # all scripts/check-*.ts
GITHUB_PAGES=true npm run build
```

`npm run lint` is run too but is informational only right now — `main`
already has pre-existing findings unrelated to any one change, so it can't
be a hard gate until that debt is paid down. Don't add *new* lint errors in
files you touch, but don't feel blocked by pre-existing ones elsewhere.

## 4. Ship it

Once the browser check and the local suite both pass:

```
git add -A && git commit -m "…"
scripts/ship.sh "PR title"
```

`scripts/ship.sh` re-runs the same checks, then pushes the branch, opens a PR
against `main`, and arms `gh pr merge --auto` so the PR merges itself the
moment CI (`.github/workflows/pr-checks.yml`) goes green — no separate manual
merge click. If you'd rather review the diff on GitHub first, skip the
script and just do the push/PR steps by hand.

## Why the extra machinery

- [.github/workflows/pr-checks.yml](.github/workflows/pr-checks.yml) is a
  **required status check** on PRs — the same `tsc` / `npm run check` /
  production build gate, enforced server-side so a broken change can't slip
  onto `main` even if a local run was skipped or a check was ignored.
- To make this a real gate (not just informational), enable branch
  protection once, in the repo settings: **Settings → Branches → Add rule**
  for `main` → require the "PR Checks / validate" status check → disallow
  direct pushes to `main`.
