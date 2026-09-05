#!/bin/bash
# Run Vale over the full lintable markdown corpus (ADR-038).
#
# Single source of truth for which tracked .md files are prose-linted.
# The exclusions mirror the per-path `BasedOnStyles =` resets in
# .vale.ini (generated artifacts, agent-facing contracts, dated
# point-in-time records) plus files Vale cannot parse. The
# vale-prose-lint hook in .pre-commit-config.yaml carries the same
# regex in its `exclude:` — keep the two in sync.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VALE_BIN="${REPO_ROOT}/.tools/vale/current/vale"

if [ ! -x "${VALE_BIN}" ]; then
  bash "${REPO_ROOT}/tools/install-vale.sh" >&2
fi

cd "${REPO_ROOT}"
lintable=()
while IFS= read -r -d '' path; do
  case "${path}" in
    .claude/*|.gc/*|.github/*|changelog.d/*|CHANGELOG.md|AGENTS.md|CLAUDE.md)
      continue
      ;;
  esac
  # ``git ls-files`` includes tracked paths deleted in the worktree. Ignore
  # those so policy can validate a cleanup before the publish step stages it.
  if [ -f "${path}" ]; then
    lintable+=("${path}")
  fi
done < <(git ls-files -z '*.md')

if [ "${#lintable[@]}" -gt 0 ]; then
  "${VALE_BIN}" --config=.vale.ini "${lintable[@]}"
fi
