#!/usr/bin/env bash
#
# install-aces-inventory-skill.sh
#
# Installs the ACES-owned asset inventory capture skill into Claude Code and
# Codex user-level skill locations on this host.
#
# Defaults to symlinks so agents read the latest source-of-truth skill from the
# ACES checkout. Use --copy only when symlinks are not viable. Idempotent:
# re-run after pulling ACES to refresh host-local links.
#
# Host targets are never clobbered blindly. A target this script owns - a
# symlink, or a copy byte-identical to the ACES source - is refreshed in place.
# Anything else is left untouched and the run fails; re-run with --force to
# overwrite it.
#
# Usage:
#   bin/install-aces-inventory-skill.sh [--aces-repo <path>] [--copy] [--dry-run] [--force]
#                                      [--no-claude] [--no-codex]
#                                      [--claude-dir <path>] [--codex-dir <path>]
#                                      [--codex-prompts-dir <path>]
#
# Options:
#   --aces-repo P       ACES checkout to install from. Defaults to ACES_REPO, then
#                       sibling checkouts such as ../aces, ../aces2, ../aces-sdl.
#   --copy              Hard-copy the skill instead of symlinking.
#   --dry-run           Print actions without writing anything.
#   --force             Overwrite host targets that differ from the ACES source.
#   --no-claude         Skip the Claude Code install target.
#   --no-codex          Skip the Codex install targets.
#   --claude-dir P      Override the Claude Code install root (default: ~/.claude/skills).
#   --codex-dir P       Override the Codex skill install root (default: ~/.codex/skills).
#   --codex-prompts-dir P
#                       Override the legacy Codex prompt install root (default: ~/.codex/prompts).

set -euo pipefail

skill_name="aces-asset-inventory-capture"
aptl_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

aces_repo="${ACES_REPO:-}"
mode="symlink"
dry_run=0
force=0
install_claude=1
install_codex=1
claude_dir="${HOME}/.claude/skills"
codex_dir="${HOME}/.codex/skills"
codex_prompts_dir="${HOME}/.codex/prompts"

usage() {
  sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

require_arg() {
  local opt="$1"
  local value="${2:-}"
  if [[ -z "${value}" || "${value}" == --* ]]; then
    echo "ERROR: ${opt} requires a path argument." >&2
    exit 2
  fi
}

absolute_dir() {
  local path="$1"
  if [[ ! -d "${path}" ]]; then
    echo "ERROR: ${path} is not a directory." >&2
    exit 1
  fi
  (cd "${path}" && pwd -P)
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --aces-repo)
      require_arg "$1" "${2:-}"
      aces_repo="$2"
      shift 2
      ;;
    --copy)
      mode="copy"
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    --force)
      force=1
      shift
      ;;
    --no-claude)
      install_claude=0
      shift
      ;;
    --no-codex)
      install_codex=0
      shift
      ;;
    --claude-dir)
      require_arg "$1" "${2:-}"
      claude_dir="$2"
      shift 2
      ;;
    --codex-dir)
      require_arg "$1" "${2:-}"
      codex_dir="$2"
      shift 2
      ;;
    --codex-prompts-dir)
      require_arg "$1" "${2:-}"
      codex_prompts_dir="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

if [[ "${install_claude}" -eq 0 && "${install_codex}" -eq 0 ]]; then
  echo "ERROR: nothing to install; both --no-claude and --no-codex were set." >&2
  exit 2
fi

has_required_skill_sources() {
  local repo="$1"

  if [[ "${install_claude}" -eq 1 && ! -f "${repo}/.claude/skills/${skill_name}/SKILL.md" ]]; then
    return 1
  fi
  if [[ "${install_codex}" -eq 1 && ! -f "${repo}/.codex-skills/${skill_name}/SKILL.md" ]]; then
    return 1
  fi
  return 0
}

find_aces_repo() {
  local candidate
  local sibling_root
  local preferred_names=(aces aces2 aces-sdl aces4)

  sibling_root="$(cd "${aptl_root}/.." && pwd -P)"

  for name in "${preferred_names[@]}"; do
    candidate="${sibling_root}/${name}"
    if [[ -d "${candidate}" ]] && has_required_skill_sources "${candidate}"; then
      absolute_dir "${candidate}"
      return 0
    fi
  done

  while IFS= read -r candidate; do
    if [[ -d "${candidate}" ]] && has_required_skill_sources "${candidate}"; then
      absolute_dir "${candidate}"
      return 0
    fi
  done < <(find "${sibling_root}" -maxdepth 1 -type d -name 'aces*' | sort)

  return 1
}

if [[ -n "${aces_repo}" ]]; then
  aces_repo="$(absolute_dir "${aces_repo}")"
else
  if ! aces_repo="$(find_aces_repo)"; then
    echo "ERROR: could not find an ACES checkout with ${skill_name}." >&2
    echo "Set ACES_REPO or pass --aces-repo <path>." >&2
    exit 1
  fi
fi

if ! has_required_skill_sources "${aces_repo}"; then
  echo "ERROR: ${aces_repo} does not contain the required ${skill_name} source(s)." >&2
  if [[ "${install_claude}" -eq 1 ]]; then
    echo "Missing Claude source: ${aces_repo}/.claude/skills/${skill_name}/SKILL.md" >&2
  fi
  if [[ "${install_codex}" -eq 1 ]]; then
    echo "Missing Codex source: ${aces_repo}/.codex-skills/${skill_name}/SKILL.md" >&2
  fi
  exit 1
fi

run() {
  if [[ "${dry_run}" -eq 1 ]]; then
    printf 'DRY-RUN:'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

is_managed_target() {
  local src="$1"
  local dst="$2"

  [[ -L "${dst}" ]] && return 0
  if [[ -f "${src}" && -f "${dst}" && ! -L "${dst}" ]]; then
    diff -q -- "${src}" "${dst}" >/dev/null 2>&1 && return 0
  fi
  if [[ -d "${src}" && -d "${dst}" && ! -L "${dst}" ]]; then
    diff -qr -- "${src}" "${dst}" >/dev/null 2>&1 && return 0
  fi
  return 1
}

install_target() {
  local src="$1"
  local dst="$2"
  local label="$3"

  if [[ -e "${dst}" || -L "${dst}" ]]; then
    if is_managed_target "${src}" "${dst}"; then
      run rm -rf -- "${dst}"
    elif [[ "${force}" -eq 1 ]]; then
      echo "FORCE: overwriting ${label} ${dst} (differs from ACES source)" >&2
      run rm -rf -- "${dst}"
    else
      echo "ERROR: refusing to overwrite ${label} ${dst}; it differs from the ACES source and is not a managed symlink." >&2
      echo "Re-run with --force to overwrite it." >&2
      exit 3
    fi
  fi

  if [[ "${mode}" == "symlink" ]]; then
    run ln -sfn "${src}" "${dst}"
  elif [[ -d "${src}" ]]; then
    run cp -R -- "${src}" "${dst}"
  else
    run cp -- "${src}" "${dst}"
  fi
  printf '%-7s %-13s %s -> %s\n' "${mode}" "${label}" "${dst}" "${src}"
}

echo "Installing ${skill_name} from ${aces_repo}"

if [[ "${install_claude}" -eq 1 ]]; then
  run mkdir -p "${claude_dir}"
  install_target \
    "${aces_repo}/.claude/skills/${skill_name}" \
    "${claude_dir}/${skill_name}" \
    "claude"
else
  echo "Skipping Claude install (--no-claude set)."
fi

if [[ "${install_codex}" -eq 1 ]]; then
  run mkdir -p "${codex_dir}" "${codex_prompts_dir}"
  install_target \
    "${aces_repo}/.codex-skills/${skill_name}" \
    "${codex_dir}/${skill_name}" \
    "codex-skill"
  install_target \
    "${aces_repo}/.codex-skills/${skill_name}/SKILL.md" \
    "${codex_prompts_dir}/${skill_name}.md" \
    "codex-prompt"
else
  echo "Skipping Codex install (--no-codex set)."
fi

echo "Done."
