#!/bin/bash
# pre-commit wrapper around Vale (ADR-038).
#
# Lints the staged .md files passed by pre-commit. If Vale is not
# installed on this machine, install it via tools/install-vale.sh
# (one-time download, idempotent) and then run. Skipping the lint when
# Vale is missing would let unlinted prose land, which is the failure
# mode the gate exists to prevent.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  exit 0
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VALE_BIN="${REPO_ROOT}/.tools/vale/current/vale"
VALE_INI="${REPO_ROOT}/.vale.ini"
INSTALL_SCRIPT="${REPO_ROOT}/tools/install-vale.sh"

if [ ! -f "${VALE_INI}" ]; then
  echo "vale-lint-hook: missing ${VALE_INI}" >&2
  exit 1
fi

if [ ! -x "${VALE_BIN}" ]; then
  if [ ! -x "${INSTALL_SCRIPT}" ]; then
    echo "vale-lint-hook: ${INSTALL_SCRIPT} missing or not executable; cannot install Vale" >&2
    exit 1
  fi
  echo "vale-lint-hook: Vale not installed; running ${INSTALL_SCRIPT} ..." >&2
  bash "${INSTALL_SCRIPT}" >&2
fi

exec "${VALE_BIN}" --config="${VALE_INI}" "$@"
