---
name: implement
description: End-to-end issue implementation — from plan through merged PR
argument-hint: <issue-number | requirement-uid>
disable-model-invocation: true
---

# Implement: $ARGUMENTS

This skill handles the ENTIRE lifecycle: plan, implement, verify, commit, push, PR, CI, reviews, fix, merge, cleanup. The user's only checkpoint is plan approval.

**Every run is driven by a GitHub issue.** The issue is the durable artifact that records why the change is being made, what requirements are in scope (if any), and how completion is reviewed. `$ARGUMENTS` may be either a GitHub issue number OR a Ground Control requirement UID; in the UID case the skill finds or creates the matching issue and runs against it. Bug fixes, refactors, dependency updates, and other requirement-free work enter the same workflow via an issue with zero requirements in scope.

---

## Phase A: Plan & Implement

### Step 1: Resolve the Issue and Branch

1. Enter plan mode.

2. Run `pwd` to capture the absolute repository root.

3. Call the `gc_get_repo_ground_control_context` MCP tool with:
   - `repo_path`: absolute path from `pwd`

4. If the tool does NOT return `status: "ok"`:
   - Stop immediately.
   - Tell the user the repository is missing a valid `.ground-control.yaml` at its root.
   - Include the tool's `suggested_ground_control_yaml` in your response and ask the user to create the file before using `/implement`.
   - Do NOT guess the Ground Control project.

5. If the tool returns `status: "ok"`, cache the following fields for use throughout the rest of the workflow:
   - `project` — used in all Ground Control MCP calls
   - `workflow.test_command` — used as the test suite command
   - `workflow.completion_command` — used as the full completion gate (falls back to test_command if null)
   - `workflow.lint_command` — used when running the linter
   - `workflow.format_command` — used when running the formatter
   - `sonarcloud` — if set, used by `/ship` later; if null, SonarCloud is skipped
   - `rules.plan_rules_content` — if non-null, treated as mandatory plan constraints in Step 4

6. **Classify `$ARGUMENTS` as either an issue reference or a requirement UID**:
   - **Issue reference**: a plain integer (`123`), a `#`-prefixed integer (`#123`), or a form like `issue:123`. In all cases, strip to the integer and treat it as the GitHub issue number.
   - **Requirement UID**: anything matching the pattern `<letters>-<letters/digits>` (examples: `GC-X001`, `OBS-042`, `DSL-101`, `TC-015`). Treat the entire string as the UID exactly as provided. Do NOT synthesize or rewrite a project prefix.
   - If the input fits neither pattern, stop and ask the user for disambiguation.

7. **If the input was a requirement UID**, resolve it to a GitHub issue:
   1. Use `gc_get_requirement` with the UID and the cached `project`. If the requirement does not exist, stop and report it.
   2. Use `gc_get_traceability` with the requirement's UUID. Look for a link with `artifact_type: GITHUB_ISSUE`.
   3. If such a link exists, note the issue number from its `artifact_identifier`.
   4. If no link exists, use `gc_create_github_issue` with the UID and `project` to create an issue and auto-link it. Note the new issue number.
   - From this point forward, treat the resolved issue number as the authoritative input. The requirement UID becomes a single entry in the `in_scope_requirements[]` list computed below.

8. **Fetch the issue** via `gh issue view <issue-number> --json number,title,body,labels,url`. Cache the full body text.

9. **Parse the `in_scope_requirements[]` list from the issue body.** The convention is a Markdown section whose heading is exactly `## Requirements` (case-insensitive match on the word `Requirements`, any heading level from `##` to `####`). The section contains a bulleted list where each bullet is a Ground Control requirement UID (matching the `<letters>-<letters/digits>` pattern), optionally followed by prose explanation.
   - If the section is present and non-empty, every valid UID bullet becomes an entry in `in_scope_requirements[]`.
   - If the section is present and empty, `in_scope_requirements[]` is empty — this is a bug/refactor/maintenance run with no formal requirements.
   - If the section is absent entirely, `in_scope_requirements[]` is empty.
   - If a UID in the section fails to resolve via `gc_get_requirement`, stop and report the broken reference.
   - If the input was a requirement UID (Step 7), ensure that UID is in `in_scope_requirements[]` — add it if missing, which also means updating the issue body to include a Requirements section.

10. **For each UID in `in_scope_requirements[]`**, fetch the full requirement via `gc_get_requirement` and cache its UUID, title, statement, status, and wave. You will use these for clause verification (Step 4.5), status transitions (Step 15), and traceability reconciliation (Step 16).

11. **Fetch the existing traceability links for the issue** via `gc_get_traceability_by_artifact` with `artifact_type: GITHUB_ISSUE` and `artifact_identifier: <issue-number>`. Cache the result — you will need it to reconcile the issue's relationship to requirements in Step 16.

12. **Switch to the issue's feature branch**: run `gh issue develop <issue-number> --checkout --base dev`. If the branch already exists, `gh` reuses it.

### Step 2: Read the Issue and Gather Context

The issue body was cached in Step 1, but re-read it carefully now for labels, comments, and any user discussion. Run `gh issue view <issue-number> --comments` to pull the comment thread too. The issue is the authoritative description of the work; everything downstream (plan, clause verification, review scope) anchors on it.

### Step 2.5: Run Codex Architecture Preflight

Preflight MUST cover every in-scope requirement, not just the first one. The preflight tool loads exactly one requirement payload per call, so grouped issues that carry multiple UIDs need one call per UID — otherwise codex never sees the statements, rationale, or existing traceability for every requirement after the first, and the returned guardrails will be incomplete.

1. Reuse the absolute repository root from Step 1.
2. **Determine the preflight call set.**
   - If `in_scope_requirements[]` is non-empty, run the call below **once per UID in the list**. Each call preflights a single requirement.
   - If `in_scope_requirements[]` is empty (requirement-free bug/refactor/maintenance run), run the call exactly once with `issue_number` alone and omit `requirement_uid`.
3. For each call in the set, call the `gc_codex_architecture_preflight` MCP tool with:
   - `issue_number`: the issue number from Step 1 (always supplied — it is the authoritative anchor for preflight in both UID-first and issue-first runs)
   - `repo_path`: absolute path from Step 1
   - `project`: the repo-local Ground Control project from Step 1
   - `requirement_uid`: the UID being preflighted in this call (omit entirely on requirement-free runs). The tool accepts either `requirement_uid` or `issue_number` alone and requires at least one; since Step 1 always produced an issue number, the issue-number-only call is the guaranteed fallback.
4. After every call in the set has returned, read any ADRs, design notes, or workflow guidance that Codex created or updated. Multiple calls may touch overlapping files — that is fine; treat the union of all guardrails as binding.
5. Treat the returned guardrails, cross-cutting concerns, and non-goals as binding unless they are clearly wrong.
6. Do NOT revert or ignore Codex-added design guidance just because implementation looks possible without it.

### Step 3: Assess Codebase Coverage

Explore the codebase to determine whether the work described in the issue is already covered by existing code:
- Search for relevant classes, methods, tests, and configurations touching the subsystems the issue describes.
- Consult the repository's existing documentation during exploration. APTL keeps design context in `docs/` — ADRs (`docs/adrs/`), architecture (`docs/architecture/`), components (`docs/components/`), and the SDL reference (`docs/sdl/`). Grep these for keywords matching the issue's subject area and read any pages that match before designing changes.
- Check if the described behavior already exists.
- For each requirement in `in_scope_requirements[]`, review its existing traceability links (IMPLEMENTS, TESTS) via `gc_get_traceability` on the requirement UUID. Some or all clauses may already be satisfied.
- Reuse the architecture-preflight guidance from Step 2.5 while assessing existing coverage and planning changes.

### Step 4: Plan or Report

- **If the work is NOT yet complete**: Plan the implementation. Identify which files need to be created or modified, what tests to write, and what approach to take. Enter plan mode.
- When `in_scope_requirements[]` is non-empty, the plan must cover every clause of every in-scope requirement. When it is empty, the plan must fully address every acceptance criterion in the issue body and any user clarifications in comments.
- Your plans must respect the coding standards and formal methods classification levels.
- You must add or update ADRs as appropriate.
- Plans must include updating the changelog, readme, and docs as appropriate.
- If designing code, remember to build off existing cross-cutting concerns, code, and patterns.
- Good code is readable, maintainable, and follows the coding standards.
- Address the concerns a FAANG L6+ engineer would have around security, performance, reliability, and scalability.
- Avoid reinventing the wheel — use existing libraries and frameworks where appropriate.
- Code should be easy to understand, test, and maintain. Simple is better than complex.
- If Step 1.3 returned non-null `rules.plan_rules_content`, treat every bullet in that content as a mandatory plan constraint for this implementation. These are repo-specific "plans MUST..." rules (e.g., framework-specific migration rules, ADR conformance checks). Apply all of them in addition to the general principles above.
- **If the work is ALREADY complete**: Report that the issue is satisfied and identify which code satisfies it. If `in_scope_requirements[]` is non-empty, verify each requirement is already linked and ACTIVE; if not, continue to Steps 15–16 (transition then reconciliation) to fix the Ground Control state without re-implementing the code.

### Step 4.4: Test-Driven Development (mandatory)

After plan approval, implement using **TDD**. This is not optional:

1. **Write the failing test first.** For each clause of each in-scope requirement AND each acceptance criterion in the issue body, write a unit test that exercises the new behavior. Run the test and confirm it fails for the right reason (missing code, not a typo / wiring issue). A test you never saw fail is not a test — it's a guess.
2. **Write the minimum production code to make the test pass.** No premature abstraction, no scope creep, no "while I'm here" cleanups. Just enough to flip the failing assertion green.
3. **Refactor with the test green.** Clean up duplication, extract helpers, rename for clarity — but only with the safety net of green tests. Re-run the test after each refactor.
4. **Repeat per clause / acceptance criterion / edge case.** Do not write a batch of production code first and then "fill in tests" afterwards — that is not TDD, it is post-hoc test-shaped coverage and fails to drive the design.
5. **Edge cases and failure modes get tests too.** Validation errors, boundary inputs, conflict states, not-found paths, status transitions. If a behavior matters enough to ship, it matters enough for a red-green cycle.
6. **Integration layers and framework-specific tests**: same loop. Write the failing test before the production code that satisfies it. Repository-policy rules from `.gc/plan-rules.md` (e.g., aptl's "MCP TypeScript servers MUST include vitest tests", "container/compose changes MUST validate against a clean `lab stop -v && lab start`") are TDD targets, not afterthoughts.
7. **If you discover during TDD that the plan is wrong**, stop and revise the plan rather than bending tests to match a flawed design. The tests are telling you something — listen to them.

Pre-existing tests around touched code must stay green at every step. If a refactor breaks an unrelated test, fix the root cause; do not silence the test.

### Step 4.5: Clause-by-Clause Verification

Before declaring implementation complete, build a mapping from every clause of every in-scope requirement AND every acceptance criterion in the issue body to the specific code (`file:line`) that satisfies it.

1. For each requirement in `in_scope_requirements[]`:
   - Re-read the requirement statement cached in Step 1.
   - Break it into individual clauses.
   - For EACH clause, identify the specific code (`file:line`) that satisfies it.
2. For each acceptance criterion stated in the issue body (or in the issue comments by the user):
   - Identify the specific code (`file:line`) that satisfies it.
3. If `in_scope_requirements[]` is empty AND the issue body has no explicit acceptance criteria, treat the issue title and description as the acceptance contract and verify the change matches.
4. If any clause or criterion is not satisfied, go back and implement it before proceeding.

Present the mapping as a checklist with the requirement UID (or `issue`) as the source label:

```
- [ ] APTL-X004 clause: "..." → Satisfied by: src/aptl/.../file.py:line
- [ ] APTL-X004 clause: "..." → Satisfied by: tests/.../test_file.py:line
- [ ] APTL-X005 clause: "..." → Satisfied by: mcp/<server>/src/file.ts:line
- [ ] issue acceptance: "..." → Satisfied by: docker-compose.yml:line
```

Do not proceed until every clause and criterion is checked off.

Traceability reconciliation (IMPLEMENTS / TESTS links) and the `DRAFT → ACTIVE` status transitions are intentionally NOT done here. They land in Steps 15–17 after CI and all reviews have passed, so Ground Control state never runs ahead of the actual code that ships.

---

## Phase B: Quality Gate

### Step 5: Quality Assurance

- run `pre-commit run --all-files` to ensure the codebase is in a healthy state.

### Step 6: Completion Gate

Implementation is NOT ready for commit until ALL of the following are verified:

1. **Completion gate passes** — run the `workflow.completion_command` cached in Step 1.3. If that field is null, fall back to `workflow.test_command`. If both are null, ask the user what the completion gate command should be for this repo (do not guess). Confirm the command exits successfully.
2. **CHANGELOG.md updated** — verify it is in `git diff --name-only` if any source files changed.
3. **Step 4.5 clause mapping was completed** — if you skipped it, go back and do it now.

If any check fails, fix it before proceeding. Do NOT move to Phase C until every check passes.

---

## Phase C: Stage, Commit, Push

### Step 7: Stage & Pre-commit Loop

1. `git add` all relevant changed files. Do NOT stage .env files, credentials, secrets, or large binaries.
2. Run `pre-commit run --all-files`.
3. If pre-commit fails:
   - Read the failure output.
   - Fix the issues.
   - Re-stage any modified files with `git add`.
   - Re-run `pre-commit run --all-files`.
   - Repeat up to 5 times. If still failing after 5 attempts, escalate to the user with the failure details.
4. When pre-commit passes, proceed.

### Step 8: Commit & Push

1. Craft a concise commit message in imperative mood (per coding standards). Example: "Add risk scoring engine for requirement prioritization"
2. NEVER include Co-Authored-By, "Generated with Claude Code", or any Claude/AI attribution in commit messages.
3. `git commit -m "<message>"`
4. `git push -u origin <branch>`

---

## Phase D: Ship

### Step 9: Create PR

1. Check if a PR already exists for this branch: `gh pr list --head <branch> --json number,url`
2. If no PR exists, create one:
   ```
   gh pr create --base dev --title "<concise title>" --body "<description with requirement reference>"
   ```
   The PR body should end with `Closes #<issue-number>` so the issue and PR are cross-linked in GitHub's UI.
3. Note the PR number and URL.

### Step 10: CI Monitor

`gh run watch` blocks indefinitely if no runner picks up the job — a real failure mode on this repo since CI is routed to a self-hosted runner pool. Use a bounded poll instead so the workflow surfaces stuck-queued conditions instead of hanging silently.

1. Find the latest workflow run: `gh run list --branch <branch> --limit 1 --json status,conclusion,databaseId,createdAt`. Cache the `databaseId` as `<id>` and the `createdAt` timestamp.
2. **Poll** `gh run view <id> --json status,conclusion` every 15 seconds. Track wall-clock elapsed time since you started polling.
3. **Queued-too-long guard.** If `status` is still `"queued"` after **5 minutes** of polling, STOP and report to the user that no runner accepted the job — most likely cause is that no `[self-hosted, linux, x64]` runner is online or available. Suggest they check the runner pool (`gh api /repos/<owner>/<repo>/actions/runners`) and confirm a runner is `online` and `idle`. Do NOT wait silently past this point.
4. **In-progress cap.** If `status` is `"in_progress"`, keep polling. Total wall-clock cap including the queued window is **45 minutes**. If the run has not reached `"completed"` by then, STOP and surface the run URL to the user — something is wrong with the runner or the workflow.
5. When `status` becomes `"completed"`:
   - If `conclusion` is `"success"`, proceed.
   - Otherwise, get failed logs: `gh run view <id> --log-failed`. Diagnose, fix, `git add`, `git commit`, `git push`, and go back to step 1 of this phase.

### Step 11: SonarCloud

**Skip this step entirely if `sonarcloud` was null in the Step 1.3 config.** Log "SonarCloud skipped — no sonarcloud block in .ground-control.yaml" and proceed to Step 12.

This step runs AFTER Step 10 (CI Monitor) reports green. A green CI run does not imply a clean SonarCloud — the quality gate and the issue list are separate from CI conclusions and must be checked independently.

Otherwise:
1. Wait 60 seconds for SonarCloud analysis to propagate after the CI run.
2. Use `get_project_quality_gate_status` with the `sonarcloud.project_key` cached in Step 1.3 to check the quality gate status for the current pull request.
3. **Pull the full open-issues list for the current PR using `$SONAR_TOKEN`.** The MCP `search_sonar_issues_in_projects` surface is the preferred interface; if it is unavailable or returns partial results, fall back to the REST API directly using the environment token:

   ```
   curl -sS -u "$SONAR_TOKEN:" \
     "https://sonarcloud.io/api/issues/search?componentKeys=<project_key>&pullRequest=<PR_NUMBER>&resolved=false&ps=500"
   ```

   - `$SONAR_TOKEN` is provided via the environment. Never hardcode, echo, or commit it.
   - Request every page until all issues are retrieved (`ps=500` plus `p=2,3,...` until `total` is covered). Do not truncate.
   - Repeat the same query with `types=SECURITY_HOTSPOT` via `api/hotspots/search?projectKey=...&pullRequest=...&status=TO_REVIEW` so security hotspots are not missed — they are a separate endpoint from plain issues.

4. **Fix ALL open issues the query returns — code-smell, bug, vulnerability, and security hotspot, regardless of severity (INFO through BLOCKER).** This follows the same "fix everything, no triage" rule as the review loop (see `Review loop rules` below): no "low priority", "out of scope", "follow-up PR", or "style-only" deferrals. If you believe a specific finding should be left unfixed (false positive, intentional pattern, etc.), STOP and ask the user for explicit permission before marking it resolved in SonarCloud or skipping it.

5. For each fix cycle:
   - Apply the fixes.
   - Re-run the local completion gate (`workflow.completion_command`) to confirm nothing regressed locally.
   - `git add`, `git commit` with message `Fix SonarCloud findings (cycle <N>)`, `git push`.
   - Re-run Step 10 (CI Monitor) so SonarCloud re-analyzes the PR.
   - After CI is green, wait 60 seconds and re-run this entire step (quality gate + issues search + hotspots search) to verify.

6. **Cycle cap: 5 iterations for SonarCloud.** If the issue list is still non-empty after 5 fix→re-analyze cycles, STOP and escalate to the user with the remaining findings.

7. Proceed to Step 12 only when: the quality gate is `OK` AND `api/issues/search?resolved=false` returns zero rows for this PR AND `api/hotspots/search?status=TO_REVIEW` returns zero rows for this PR.

## Review loop rules (apply to every review step in this phase)

Every review step below (Codex cross-model, test quality review) follows the **same loop**:

1. **Invoke the review.**
2. **Read the FULL output.** Do not stop after the first few findings.
3. **Fix ALL issues the reviewer identifies — blocking or not, severity-rated or not, "nitpick" or not.** There is no triage bucket. "Low priority", "nice to have", "follow-up PR", "out of scope" are not valid reasons to skip a finding.
4. **If you cannot or believe you should not fix a specific finding**, you MUST stop and ask the user for explicit permission to leave it unfixed. Do not decide unilaterally. State the finding, why you think it should be skipped, and wait for the user's answer. Resume only after they explicitly confirm.
5. **Re-run the SAME review after fixing.** Do not assume your fixes are complete — the re-run is the verification.
6. **Repeat until the reviewer reports zero findings, OR the cycle cap is hit.**
7. **Cycle cap: 5 iterations per review step.** If a review still reports findings after 5 invoke→fix→re-run cycles, STOP and escalate to the user with the full history of findings, fixes, and remaining issues. Do not loop indefinitely.

For every cycle, after applying fixes, commit and push BEFORE re-running the review so the reviewer sees the updated tree. Format every fix commit as `Fix review findings (<reviewer>, cycle <N>)` so the loop history is visible in git log.

### Step 12: Cross-Model Review (Codex)

`gc_codex_review` runs two focused codex reviewers — a core production-readiness reviewer and a dedicated application-security reviewer — against a single pre-computed diff. By default the reviewers run sequentially (set `GC_CODEX_REVIEW_PARALLEL=2` to opt back into parallel execution). Both post their findings as inline PR review comments with a reviewer-tagged title (`[core]` or `[security]`). The tool returns a single deduplicated list; you then drive a per-finding fix/verify loop via `gc_codex_verify_finding`, which handles the GitHub API bookkeeping for you.

1. Run `pwd` to capture the absolute repository root.
2. Determine the pull request number for the current branch: `gh pr view --json number`. Cache it.
3. Call the `gc_codex_review` MCP tool with:
   - `repo_path`: absolute path from `pwd`
   - `base_branch`: `dev`
   - `pr_number`: the PR number from step 2
4. The tool returns `{pr_number, finding_count, comments: [{comment_id, thread_id, reviewer, path, line, title, html_url}, ...], reviewers, core_review_text, security_review_text}`. Each comment carries a `reviewer` field (`core` or `security`) so you can triage attention, but the fix/verify loop below is the same regardless. Codex has already posted each finding as an inline PR review comment — you do NOT need to post anything yourself.
5. If `finding_count` is 0, skip to Step 13.
6. Otherwise, for EACH entry in `comments`, run the following fix/verify loop:
   1. Read the comment body if needed: `gh api /repos/<owner>/<repo>/pulls/comments/<comment_id>`.
   2. Fix the finding locally. Apply the same "fix every finding, no triage, ask user permission if you will not fix" rules from the **Review loop rules** section above.
   3. Run the local completion gate to make sure nothing regressed locally.
   4. Call `gc_codex_verify_finding` with `repo_path`, `pr_number`, and the `comment_id`. Codex will read your local changes and decide:
      - **`status: "resolved"`** — the review thread has already been marked resolved on GitHub. Move on to the next comment.
      - **`status: "unresolved"`** — codex posted a threaded reply with `reply_body` containing concrete new directions. Read `reply_body`, fix per those directions, and re-invoke `gc_codex_verify_finding`. **Per-finding cap: 2 verify calls.** If the third call would be needed, STOP and escalate to the user with the finding, your fix history, and the latest `reply_body`.
7. After all findings in the returned `comments` list are marked `resolved`, commit and push the fixes (one commit per fix cycle, message `Fix review findings (codex, cycle <N>)`), then re-invoke `gc_codex_review` with the same arguments to confirm no new issues surfaced after your fixes.
8. **Overall step cap: 5 iterations of `gc_codex_review`.** If the fifth invocation still returns findings, STOP and escalate to the user.

**Tool shape**: `gc_codex_verify_finding` accepts only `repo_path`, `pr_number`, and `comment_id`. It reads the comment directly from GitHub; do not try to paraphrase the finding or pass additional context through the tool.

### Step 13: Test Quality Review

**CRITICAL: You MUST use the Skill tool to invoke the review-tests skill.**

1. Call the Skill tool with `skill="review-tests"` to invoke the test quality review.
2. Apply the **Review loop rules** above: fix every finding, ask user permission for anything you will not fix (including "warning" level — the review loop rules apply to warnings too, there is no triage bucket), re-invoke `skill="review-tests"` after each fix cycle, cap at 5 cycles.

### Step 14: Final CI re-verification

After both review steps (12-13) have reported zero findings (or you have documented user-approved exceptions):

1. Verify the branch is pushed with the latest fix commits.
2. Re-run Step 10 (CI Monitor) to confirm CI is still green after the review fixes.
3. Re-run Step 11 (SonarCloud) — or skip again if `sonarcloud` was null.
4. If either re-check fails, loop back through the appropriate review step — the cycle cap (5) applies per review step, not total.

### Step 15: Transition In-Scope Requirements to ACTIVE

The status transition MUST happen BEFORE traceability reconciliation (Step 16). The Ground Control API enforces `IMPLEMENTS → ACTIVE`: any `gc_create_traceability_link` call with `link_type: IMPLEMENTS` against a `DRAFT` requirement returns `422 requirement_not_active`. Reconciling first therefore produces 10+ silent-looking failures; transitioning first is the only order that actually works.

Semantically, moving a requirement from DRAFT to ACTIVE is the point at which the team commits to its statement. Once real code exists pointing at it, the requirement is no longer a proposal — it's a contract. The transition locks in the statement, and the subsequent reconciliation in Step 16 records the code that fulfills it.

For each UID in `in_scope_requirements[]`:
- Use the `gc_transition_status` MCP tool to transition the requirement from `DRAFT` to `ACTIVE`.
- If the requirement was already `ACTIVE`, skip it.
- If the requirement was in any other state (`DEPRECATED`, `ARCHIVED`), STOP and surface the anomaly to the user — transitioning out of those states is a user decision.

If `in_scope_requirements[]` is empty, this step is a no-op (bug/refactor/maintenance run with no formal requirements). Proceed to Step 16 anyway — the reconciliation step still needs to run to catch drift on other requirements whose files this diff touched.

### Step 16: Reconcile Traceability Links Against the Diff

Now that CI and all reviews are green AND every in-scope requirement is ACTIVE, reconcile the Ground Control traceability graph against the actual diff. This MUST happen AFTER Step 15 (transition) and BEFORE Step 19 (Report). Doing the reconciliation earlier either fails outright (IMPLEMENTS against DRAFT) or records links against unproven code if the review cycle rejects the work.

**Reconciliation is not the same as "create links for the in-scope requirements"**. Even runs with zero in-scope requirements (pure bug fixes, refactors, maintenance) must reconcile, because the diff may have touched files that were already linked to OTHER requirements and those links may now be stale.

1. **Compute the touched file set.** Run `git diff --name-status <base-ref>...HEAD` to get every added (`A`), modified (`M`), deleted (`D`), renamed (`R`), and copied (`C`) file in this branch. Cache the full list.

   Resolve `<base-ref>` in the same order the codex review already uses so reconciliation works in fully-hydrated GitHub clones, local-only checkouts, and disconnected workstations:
   1. `origin/dev` — the canonical remote-tracking ref. Verify it exists with `git rev-parse --verify origin/dev` before using.
   2. `dev` — the local branch. Verify with `git rev-parse --verify dev`.
   3. `origin/main` — fallback for repos whose default base is not `dev`.
   4. `main` — fallback for local-only clones of main-based repos.
   5. If none of the above resolve, run `git fetch origin dev` and retry the list. If the fetch itself fails (no network, no remote), STOP and surface a clear error — reconciliation cannot run without a base ref, and silently falling back to an empty diff would under-report drift.

2. **Process deleted and renamed files first.**
   For every deleted file `path`:
   - Call `gc_get_traceability_by_artifact` with `artifact_type: CODE_FILE` and `artifact_identifier: path`. Repeat with `artifact_type: TEST`. This returns every IMPLEMENTS/TESTS link pointing at that path.
   - For each link found: inspect the diff to determine whether the behavior moved to a new file (rename or split) or was genuinely removed.
     - If the behavior moved to an identifiable new file, delete the stale link via `gc_delete_traceability_link` and create a replacement via `gc_create_traceability_link` pointing at the new path with the same `link_type` and the same source requirement.
     - If the behavior was removed entirely and the linked requirement no longer has any implementation, STOP. Ripping out the only implementation of a requirement is a user decision, not an agent decision. Surface this to the user with the requirement UID, the deleted file, and the suggestion that either the requirement should be deprecated or the behavior should be reimplemented. Wait for explicit direction.
   For every renamed file `old_path → new_path`:
   - Call `gc_get_traceability_by_artifact` with the old path. For each matching link, delete it and re-create it with the new path.

3. **Process modified files.**
   For every modified file `path`:
   - Call `gc_get_traceability_by_artifact` with `artifact_type: CODE_FILE` (or `TEST` for test files) and `artifact_identifier: path` to find every existing link.
   - For each existing link, inspect the modified file and decide: does this file still satisfy the linked requirement?
     - **Yes, unchanged** — leave the link alone.
     - **Yes, but the behavior now spans a different file too** — create additional links covering the new location(s).
     - **No, the behavior moved out of this file** — delete the stale link and create replacement(s) at the new location(s).
   - Additionally, inspect the modified file for behaviors that satisfy requirements which were NOT previously linked. This is the case where a change incidentally touches code that implements an under-linked requirement. Create new links for any such matches. Bound the search to requirements whose subject area the modified file plausibly touches; do not exhaustively compare every requirement to every file.

4. **Process added files.**
   For every added file `path`:
   - Determine which requirement(s) this file satisfies. If the file is part of the work described by an in-scope requirement, link it there. If the file is incidental (test helper, fixture, generated file), it may have no requirement link — that is fine.
   - Create an IMPLEMENTS link (for production code) or TESTS link (for test files) via `gc_create_traceability_link` for each requirement the file satisfies.

5. **Ensure every in-scope requirement has coverage appropriate to its nature.**
   This step has two modes depending on what Step 4 concluded:

   **Mode A — the diff implemented the work.** This is the common case: the run added or modified files that implement at least one in-scope requirement. For each UID in `in_scope_requirements[]`:
   - Call `gc_get_traceability` on the requirement's UUID.
   - **IMPLEMENTS coverage is always required.** Every in-scope requirement must have at least one IMPLEMENTS link pointing at a file touched by this diff. The shape of "implementation" depends on what the requirement demands:
     - **Code requirements** (functional behavior, new endpoints, new entities, services, migrations) — IMPLEMENTS points at the production code file(s) that realize the behavior.
     - **Documentation requirements** (invariants, conventions, schemas, ADR-recorded decisions) — IMPLEMENTS points at the authoritative documentation file (ADR, `SCHEMA.md`, `docs/*.md`) where the invariant or convention is declared.
     - **Configuration requirements** (repo config, workflow config, policy files, ground-control.yaml sections) — IMPLEMENTS points at the config file or schema file that encodes the requirement.
     - **Workflow requirements** (CI steps, hooks, policy rules) — IMPLEMENTS points at the workflow file, hook script, or policy script.
     If the diff does not touch any file that implements a given in-scope requirement, either add the implementation (go back to Step 4) or the requirement is not actually in scope and should be removed from the issue body before reconciliation proceeds.
   - **TESTS coverage is conditional.** Add a TESTS link when the diff introduces or touches an automated test that verifies the requirement — pytest unit/integration test, vitest test for an MCP server or web frontend, hypothesis property test, or any other form of executable verification. TESTS is NOT required when the requirement is satisfied purely by documentation, configuration, or structural invariants that have no executable behavior to test (for example: "the README shall document the lab-start workflow", "the repo shall declare its sonar config in `.ground-control.yaml`"). In that case the IMPLEMENTS link alone is the complete coverage record.
   - **Do not fabricate test links** just to satisfy this step. If a requirement has testable behavior and no test was added, go back to Step 4.4 (TDD) and add the missing test; do not paper over the gap with a link to an unrelated file.
   - **Never link the diff to a requirement it does not satisfy** just to satisfy this step. Ripping out real coverage and linking a plausible-looking neighbor is worse than leaving a gap — STOP and surface the mismatch to the user instead.

   **Mode B — Step 4 concluded the work is already complete (reconciliation-only run).** In this mode the code already ships and the diff has no new implementation files. Forcing an IMPLEMENTS link onto a file in the diff would be wrong — there may not be one. Instead:
   - Call `gc_get_traceability` on the requirement's UUID.
   - **Accept existing IMPLEMENTS coverage.** If the requirement already has one or more IMPLEMENTS links pointing at files that currently exist in the repo and that still satisfy the requirement (verify with a quick read — the code hasn't been ripped out), that coverage counts as complete. Do NOT fabricate new links against files in this diff just to satisfy the checklist.
   - **Backfill only when nothing is linked.** If the requirement is in scope for this issue but has zero existing IMPLEMENTS links, the graph really is under-linked. Locate the file(s) in the repo (not necessarily in the diff) that implement the requirement and create the missing IMPLEMENTS link(s) via `gc_create_traceability_link`. The link target is the file that actually implements the behavior, regardless of whether the current diff touched it.
   - **TESTS rules from Mode A still apply** — conditional on testable behavior, no fabrication, no plausible-neighbor linking.
   - If Mode B discovers that a requirement has NO implementing file anywhere in the repo, STOP and surface to the user. That means either the requirement should be demoted (DEPRECATED) or the implementation is genuinely missing and the run should drop into Mode A to build it.

6. **Reconcile the issue → requirement links (both directions).**
   The `## Requirements` section of the issue body is the source of truth for which requirements this issue covers. Reconciliation must make the Ground Control graph match that list exactly — which means both adding missing links AND deleting stale ones.
   - **Add missing links.** For each UID in `in_scope_requirements[]`, ensure there is a traceability link with `artifact_type: GITHUB_ISSUE` and `artifact_identifier: <issue-number>` on the requirement, pointing at this run's issue. Create it via `gc_create_traceability_link` if missing.
   - **Delete stale links.** Call `gc_get_traceability_by_artifact` with `artifact_type: GITHUB_ISSUE` and `artifact_identifier: <issue-number>` to list every requirement currently linked to this issue. For each returned link, if the requirement UID is NOT in `in_scope_requirements[]`, delete the link via `gc_delete_traceability_link`. This catches the case where an issue was narrowed from `[GC-A, GC-B]` down to `[GC-A]` and leaves no orphan pointers from GC-B.
   - Stale links from the current issue to requirements in `in_scope_requirements[]` (a no-op) are fine; duplicate-create is intentionally rejected by `gc_create_traceability_link`, so re-adding is safe.

Reconciliation is idempotent: running it on a branch where the GC graph is already correct is a no-op. Running it on a branch where the graph has drifted fixes the drift in both directions.

### Step 17: Verify Ground Control State Landed

1. For each UID in `in_scope_requirements[]`:
   - Re-fetch with `gc_get_requirement` and confirm status is `ACTIVE` (Step 15 should have transitioned it).
   - Re-fetch with `gc_get_traceability` and confirm the expected IMPLEMENTS, TESTS, and GITHUB_ISSUE links are present (Step 16 should have recorded them).
2. Re-run the deleted/renamed/modified audit from Step 16 point-by-point: every file in the diff should either have up-to-date links or have been intentionally left un-linked.
3. If anything is missing or still drifted, loop back to the responsible step and fix: Step 15 for status drift, Step 16 for link drift. Do not proceed to Step 18 (close issue) or Step 19 (report) until Ground Control state matches reality across every file in the diff and every in-scope requirement.
4. **Never declare success on silent failures.** If any `gc_create_traceability_link` / `gc_delete_traceability_link` / `gc_transition_status` call returned a non-2xx response during Steps 15–16, treat that as a failure, surface the error to the user if it is not clearly fixable (e.g., a permission issue or an API constraint you cannot work around), and loop back to correct the root cause. A batch of 10 parallel calls where 7 succeeded and 3 failed is not "mostly done" — it's broken.

### Step 18: Close the Issue

Close the GitHub issue now via `gh issue close <issue-number>`. The work is done, the PR records it, and GitHub's auto-close on merge is unreliable — close it yourself.

### Step 19: Report (DO NOT MERGE)

**You MUST NOT merge the PR. You MUST NOT run `gh pr merge`. The user reviews and merges.**

Provide a final summary:
- Issue number and title
- `in_scope_requirements[]` — each UID + title, with its new status
- Files created, modified, renamed, or deleted
- Traceability reconciliation summary — how many links were added, deleted, updated, and which requirements gained coverage
- Review findings and fixes (if any)
- Test quality review findings and fixes (if any)
- Confirmation: CI green, SonarCloud passed (or skipped if not configured), PR ready for user review
- PR URL
