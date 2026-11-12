#!/usr/bin/env bash
# Local CI: runs the checks of the old hosted workflow and reports each one as
# a commit status on HEAD, so a pull request shows the same two checks that
# branch protection requires. Hosted Actions are no longer used.
#
# Usage: scripts/ci-local.sh [--no-report]
# Needs a clean tree (the result is attached to the commit, not the working
# copy), a pushed HEAD and an authenticated `gh` for reporting.
set -uo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

report=1
[[ "${1:-}" == "--no-report" ]] && report=0

if [[ -n "$(git status --porcelain)" ]]; then
  echo "ci-local: the working tree is not clean; commit or stash first" >&2
  exit 2
fi

sha="$(git rev-parse HEAD)"
repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null || true)"
if [[ $report -eq 1 && -z "$repo" ]]; then
  echo "ci-local: cannot resolve the GitHub repository (gh auth status)" >&2
  exit 2
fi

post() { # context state description
  [[ $report -eq 1 ]] || return 0
  gh api "repos/$repo/statuses/$sha" -f state="$1" -f context="$2" \
    -f description="$3" >/dev/null
}

run_check() { # context command...
  local context="$1"
  shift
  post pending "$context" "running locally"
  if "$@"; then
    post success "$context" "passed locally on $(date -u +%Y-%m-%dT%H:%MZ)"
    echo "ci-local: $context passed"
  else
    post failure "$context" "failed locally"
    echo "ci-local: $context FAILED" >&2
    return 1
  fi
}

lint_and_test() {
  cargo fmt --all --check &&
    cargo clippy --all-targets --all-features -- -D warnings &&
    cargo test --all-features
}

failed=0
run_check "Format, lint, and test" lint_and_test || failed=1
run_check "Minimum Rust version" cargo +1.85.0 check --all-features || failed=1
exit $failed
