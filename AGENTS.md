# Agent Instructions

This repository (APTL — Advanced Purple Team Lab) uses Ground Control for
requirements management and workflow automation.

## Ground Control Context

This repo's Ground Control project id, workflow commands, SonarCloud
settings, and plan rules live in `.ground-control.yaml` at repo root
(with larger rule files under `.gc/`). Agents read it via the
`gc_get_repo_ground_control_context` MCP tool, which returns the full
workflow config in a single call.

Key facts encoded there today:

- Ground Control project: `aptl`
- GitHub repo: `Brad-Edwards/aptl`
- Test / completion command: `pytest`
- Lint / format command: `pre-commit run --all-files`
- SonarCloud project key: `Brad-Edwards_aptl` (org: `brad-edwards`)
- Plan rules: `.gc/plan-rules.md`

## Skill Installation

The canonical agent-neutral implement and review-tests skills are
maintained in the Ground Control repo at `skills/implement/SKILL.md`
and `skills/review-tests/SKILL.md`. They are installed at the **user
level** — not committed per-repo — by running, from a Ground Control
checkout:

```bash
bin/install-skills.sh
```

That script symlinks the canonical skills into:

- `~/.claude/skills/` (Claude Code)
- `~/.codex/prompts/` (Codex)

Both Claude and Codex therefore read the same source-of-truth SKILL.md.
Re-run the script after pulling Ground Control to refresh. Use `--copy`
on hosts without symlink support and `--no-codex` if Codex isn't
installed locally.

This repo intentionally does **not** ship `.claude/skills/implement/`
or `.claude/skills/review-tests/` — those were per-repo duplicates
superseded by Ground Control PR #792. Other repo-local skills under
`.claude/skills/` (e.g. `ship`, `stage`, `gh-workflow-monitor`,
`wave-issue-coverage`) remain in place because they are aptl-specific
or not yet promoted to the agent-neutral set.

## ACES Asset Inventory Capture Skill

The asset inventory capture methodology and reusable capture tooling are
maintained in the ACES repo. Agents working APTL inventory issues should
install the ACES skill at the user level from an ACES checkout:

```bash
bin/install-aces-inventory-skill.sh --aces-repo ../aces
```

Set `ACES_REPO=../aces2` or pass `--aces-repo <path>` when the local ACES
checkout uses a different directory name. The installer symlinks the ACES
skill into:

- `~/.claude/skills/aces-asset-inventory-capture`
- `~/.codex/skills/aces-asset-inventory-capture`
- `~/.codex/prompts/aces-asset-inventory-capture.md`

Use that installed skill together with the ACES inventory docs when
capturing evidence or encoding inventory results for APTL.

## Ground Control Overview

Ground Control is the requirements / traceability / workflow system this
repo plans against. Agents interact with it through MCP tools
(`gc_*`), which provide:

- **Requirements** — fetch by UID, list by project / wave / status,
  inspect history and diffs.
- **Traceability** — create `IMPLEMENTS` and `TESTS` links between
  requirements and code / test artifacts so coverage is queryable.
- **Status transitions** — move requirements through their lifecycle
  (e.g. `DRAFT` → `IN_PROGRESS` → `IMPLEMENTED` → `VERIFIED`) using
  the workflow rules defined in Ground Control.
- **Repo context** — `gc_get_repo_ground_control_context` returns this
  repo's `.ground-control.yaml` configuration in one call.

## Workflow

The `/implement` skill (installed at user level — see above) drives the
end-to-end loop. Summary for agents working in this repo:

1. **Fetch the requirement.** Use `gc_get_requirement` with the full
   UID exactly as it exists in Ground Control. Do not synthesize or
   rewrite requirement prefixes.
2. **Plan.** Apply `.gc/plan-rules.md` — in particular: Python changes
   need pytest coverage in `tests/`; MCP TypeScript changes need
   vitest coverage in that server's `tests/`; web frontend changes
   need vitest coverage in `web/tests/`; changes under
   `mcp/aptl-mcp-common` require every dependent MCP to rebuild and
   pass tests; changes to `docker-compose.yml`, container Dockerfiles,
   or `config/` must be validated by a clean
   `aptl lab stop -v && aptl lab start` on a fresh machine.
3. **Implement.** Make the code change.
4. **Verify locally.** Run `pre-commit run --all-files` (lint +
   format + the gated test suites) before declaring done. Run the
   relevant test command directly (`pytest`, `npx vitest run`, etc.)
   when iterating.
5. **Create traceability.** Create `IMPLEMENTS` and `TESTS`
   traceability links from the requirement to the code / test
   artifacts that satisfy it.
6. **Transition status.** Move the requirement to the next workflow
   state via `gc_transition_status` once the work is complete and
   linked.

## Workflow Notes

- Pass full requirement UIDs exactly as they exist in Ground Control.
  Do not synthesize or rewrite requirement prefixes.
- Keep repo-native checks, docs, and Ground Control policy in sync.
  Do not rely on agent-specific user-level hooks as the only
  enforcement layer.
- Skipping tests or pre-existing problems as "not my scope" is not
  acceptable — surface them to the user (per repo `CLAUDE.md`).

<!-- TODO: document any aptl-specific `make`-style entry points or a
     dedicated `/ship` workflow once they are promoted into the
     agent-neutral skill set. -->
