---
name: wave-issue-coverage
description: For each DRAFT requirement in a given Ground Control wave (or all waves), ensure a GitHub issue covers it and is bidirectionally linked. Use when the user asks to "cover wave N requirements with issues", "back-fill issues for draft requirements", or similar. Requires the Ground Control MCP and `gh` CLI.
---

# Wave Issue Coverage

Back-fill GitHub issue coverage for DRAFT Ground Control requirements in a given wave.

## Inputs

- **wave**: integer wave number (e.g. `1`, `2`, `3`) OR the literal string `all`
  - `all` → process every wave that has DRAFT requirements, smallest wave first

## Preconditions

1. Read `.ground-control.yaml` at the repo root via `gc_get_repo_ground_control_context` to obtain:
   - `project` — Ground Control project identifier
   - `github_repo` — `owner/repo` for `gh` calls
   These values are passed to every MCP and `gh` call in this workflow. Do not hard-code them.
2. The GC MCP server (`mcp__ground-control__*`) must be available.
3. `gh auth status` must be authenticated with write access to `github_repo`.

## Workflow

### 1. Resolve the requirement list

Call `gc_list_requirements` with `project=<project>`, `status=DRAFT`, `size=200`, and:
- `wave=<N>` if a single wave was given, OR
- no `wave` filter if `all` was given (then group results by wave and process oldest wave first).

Capture the full list of `(uid, id, title, requirement_type, priority, wave)` tuples. This is the work list.

### 2. Choose progress tracker

Pick based on the size of the work list:

| Count | Tracker |
|---|---|
| ≤ 25 | `TaskCreate` — one task per requirement, processed in order |
| > 25 | A temp file at `/tmp/wave-issue-coverage-<wave>-<timestamp>.md` with a checkbox per requirement; update inline as each completes |

For the temp-file path, use a single in-progress `TaskCreate` task ("Process wave N coverage — see temp file") so the user still sees forward motion in their TaskList.

### 3. Process sequentially — DO NOT parallelize

For each requirement, in order:

1. **Check existing GC traceability**
   `gc_get_traceability` with the requirement UUID. Note any existing `GITHUB_ISSUE` artifact links.

2. **Search GitHub for the UID**
   `gh issue list --repo <github_repo> --state all --search "<UID> in:title,body" --json number,title,state`

3. **Search GitHub for topic overlap (only if no UID match)**
   Run a small number of focused keyword searches drawn from the requirement title/statement. The goal is to catch issues that pre-date the UID convention or were filed under a different name. Pick the strongest 1–3 keywords; do not flood with searches.

4. **Decide coverage**
   - **Issue found that fully or substantially covers the requirement** → link it and update its body (step 5).
   - **Issue found that partially covers** → link it (step 5) AND create a new issue for the remaining scope (step 6).
   - **No relevant issue** → create a new issue (step 6).

5. **Link existing issue + update body**
   - If GC has no link to the issue yet, call `gc_create_traceability_link` with `link_type=DOCUMENTS` (DRAFT requirements reject `IMPLEMENTS` — see Notes).
   - Read the current issue body; if it does not already have a `## Requirements` section, prepend one:
     ```markdown
     ## Requirements

     - <UID> — <Requirement Title>
     ```
     If it has one but the UID is missing, add the bullet to the existing list. Save via `gh issue edit <n> --body-file <tempfile>`.
   - Apply labels (step 7).

6. **Create new issue**
   - Call `gc_create_github_issue` with `uid=<UID>`, `project=<project>`, `repo=<github_repo>`, `extra_body="## Requirements\n\n- <UID> — <Title>"`, and `labels=[...]` (step 7 list).
   - The MCP tool will return a warning that the auto-link failed because the requirement is DRAFT (it tries `IMPLEMENTS`). Manually create the link with `gc_create_traceability_link` using `link_type=DOCUMENTS`.

7. **Tag the issue**
   Every issue touched or created in this workflow must carry, at minimum:
   - `requirement`
   - `wave-<N>` (the requirement's wave; create the label if it does not exist via `gh label create wave-<N> --description "Wave <N> requirement" --color B60205`)

   Plus 1–3 topic-specific labels chosen from the repo's existing label set. Pick conservatively; do not invent new topic labels. Common picks:
   - GC-D* (GitHub integration) → `integrations`, `backend`
   - GC-E* (traceability semantics) → `domain`, `backend`
   - GC-L* (MCP tools) → `mcp-grc`, `api`
   - GC-C* (analysis / quality gates) → `quality`, `ci-cd`
   - GC-Q* (web UI) → `frontend`, `ui`
   - GC-O* (workflow / agents) → `agents`, `workflow`, `documentation`
   - GC-P* (platform / security) → `security` or `auth`
   - TC-* (test management) → `testing`, plus `data-model` / `domain` / `frontend` as fits

   Apply with `gh issue edit <n> --add-label "a,b,c"`. If a pre-existing issue already has labels, add to them; do not strip.

8. **Mark the task / temp-file row complete** and move to the next requirement. Never advance two requirements in parallel.

### 4. Report back

Single short summary: how many requirements processed, how many already had coverage, how many issues created. Do NOT enumerate everything done — the user will read the TaskList or temp file if they want detail.

## Notes

- **DRAFT requirements + IMPLEMENTS link**: `gc_create_traceability_link` with `link_type=IMPLEMENTS` rejects DRAFT requirements with `422`. Always use `DOCUMENTS` for issue → DRAFT links. This matches what `gc_create_github_issue` is *trying* to do but the auto-link inside that tool currently uses `IMPLEMENTS` and silently warns; do the link yourself.
- **Issue body `## Requirements` section**: per `docs/DEVELOPMENT_WORKFLOW.md`, the `/implement` skill parses this section. Format must be a markdown H2 named exactly `## Requirements` followed by a bulleted list, each bullet starting with the UID. This is what makes the issue routable through `/implement` later.
- **Sequential, not parallel**: the tooling will let you fan out, but the user has explicitly asked for serial processing every time. Honor it.
- **Don't invent labels**: if a topic label doesn't exist in `gh label list`, skip it rather than creating it. The only label this skill creates is `wave-<N>` when missing.
- **Idempotency**: re-running this skill on the same wave should be a no-op for already-covered requirements. The presence of a `GITHUB_ISSUE` traceability link AND a `## Requirements` section listing the UID AND `requirement` + `wave-<N>` labels means there is nothing to do; move on.

## Quick reference — MCP calls

```text
gc_get_repo_ground_control_context(repo_path=<absolute repo path>)
gc_list_requirements(project, status="DRAFT", wave=<N>, size=200)
gc_get_traceability(id=<requirement UUID>)
gc_create_github_issue(uid, project, repo, extra_body, labels)
gc_create_traceability_link(requirement_id, artifact_type="GITHUB_ISSUE",
                            artifact_identifier="#<n>", artifact_title,
                            artifact_url, link_type="DOCUMENTS")
```
