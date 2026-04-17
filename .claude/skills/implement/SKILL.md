---
name: implement
description: End-to-end requirement implementation — from plan through merged PR
argument-hint: <requirement-uid>
disable-model-invocation: true
---

# Implement Requirement: $ARGUMENTS

This skill handles the ENTIRE lifecycle: plan, implement, verify, commit, push, PR, CI, reviews, fix, merge, cleanup. The user's only checkpoint is plan approval.

---

## Phase A: Plan & Implement

### Step 1: Fetch Requirement and Ensure GitHub Issue Exists

1. Enter plan mode.

2. Use the `gc_get_requirement` MCP tool with uid `GC-$ARGUMENTS` to fetch the requirement details. Note the requirement's UUID, title, statement, status, and wave.

3. Use the `gc_get_traceability` MCP tool with the requirement's UUID to check for existing traceability links. Look for a link with artifact_type `GITHUB_ISSUE`.

4. If NO GitHub issue link exists:
   - Use the `gc_create_github_issue` MCP tool with uid `$ARGUMENTS` to create a GitHub issue and auto-link it.

5. If a GitHub issue link DOES exist, note the issue number from the artifact_identifier.

6. Run `gh issue develop <issue-number> --checkout --base dev` to switch to the issue branch.

### Step 2: Read the GitHub Issue

Run `gh issue view <issue-number>` to read the full issue details including description, labels, and comments.

### Step 3: Assess Codebase Coverage

Explore the codebase to determine whether the requirement described in the issue is already satisfied by existing code:
- Search for relevant classes, methods, tests, and configurations
- Check if the described behavior already exists
- Review any existing traceability links (IMPLEMENTS, TESTS) from Step 1

### Step 4: Plan or Report

- **If the requirement is NOT yet met**: Plan the implementation. Identify which files need to be created or modified, what tests to write, and what approach to take. Enter plan mode.
- Your plans must respect `docs/reference/coding-standards.md` as the source of truth for coding standards and formal-methods classification (`FM0`-`FM3`).
- Every plan that changes semantic or stateful behavior must declare its classification (`FM0`, `FM1`, `FM2`, or `FM3`) and cite the required artifacts for that level.
- `FM1+` plans must name the invariants being introduced or changed and include invariant-driven tests.
- `FM3` plans must include an abstract state-machine model when the change introduces or materially changes branching, re-entry, concurrency barriers, or lifecycle/result-contract semantics.
- Plans must also state when formal methods are not required, to avoid cargo-cult usage on purely structural changes.
- You must add or update ADRs as appropriate.
- Plans must include updating the changelog, readme, and docs as appropriate.
- If designing code, remember to build off existing cross-cutting concerns, code, and patterns
- Good code is readable, maintainable, and follows the coding standards
- Address the concerns a FAANG L6+ engineer would have around security, performance, reliability, and scalability
- Avoid reinventing the wheel - use existing libraries and frameworks where appropriate
- Code should be easy to understand, test, and maintain. Simple is better than complex.
- Plans that add or change Python code MUST include corresponding pytest tests in `tests/`.
- Plans that add or change MCP TypeScript servers MUST include corresponding vitest tests.
- Plans that add or change web frontend code MUST include corresponding vitest tests.
- **If the requirement IS already met**: Report that the requirement is satisfied and identify which code satisfies it.

### Step 4.5: Clause-by-Clause Verification

Before declaring implementation complete:
1. Re-read the requirement statement from Step 1.
2. Break it into individual clauses and acceptance criteria.
3. For EACH clause, identify the specific code (file:line) that satisfies it.
4. If any clause is not satisfied, go back and implement it before proceeding.

Present the mapping as a checklist:
- [ ] Clause: "..." → Satisfied by: file.py:line
- [ ] Clause: "..." → Satisfied by: file.py:line

Do not proceed to Step 5 until every clause is checked off.

### Step 5: Ensure Traceability Links

After implementation is complete (or if already implemented):
- use the `gc_create_traceability_link` MCP tool to create any missing links:
  - `IMPLEMENTS` links from the requirement to **every** code file that implements it — entities, enums, repositories, services, controllers, migrations, and MCP tool files. Link all substantive files, not just the top 3. DTOs and command records may be omitted.
  - `TESTS` links from the requirement to the test files that verify it
  - Only create links that don't already exist (check the traceability data from Step 1).
- use the `gc_transition_status` MCP tool to transition the requirement to `ACTIVE` if it was `DRAFT`.

Do not update the Changelog if all you did was operate Ground Control tools.

---

## Phase B: Quality Gate

### Step 6: Quality Assurance

- run `pre-commit run --all-files` to ensure the codebase is in a healthy state.

### Step 7: Completion Gate

Implementation is NOT complete until ALL of the following are verified:

1. **Tests pass** — run `.venv/bin/pytest tests/ -v --tb=short` and confirm all tests pass.
2. **CHANGELOG.md updated** — verify it is in `git diff --name-only` if any source files changed.
3. **Traceability links exist** — re-fetch with `gc_get_traceability` and confirm IMPLEMENTS and TESTS links are present.
4. **Requirement status is ACTIVE** — re-fetch with `gc_get_requirement` and confirm status.
5. **Step 4.5 clause mapping was completed** — if you skipped it, go back and do it now.

If any check fails, fix it before proceeding. Do NOT move to Phase C until every check passes.

---

## Phase C: Stage, Commit, Push

### Step 8: Stage & Pre-commit Loop

1. `git add` all relevant changed files. Do NOT stage .env files, credentials, secrets, or large binaries.
2. Run `pre-commit run --all-files`.
3. If pre-commit fails:
   - Read the failure output.
   - Fix the issues.
   - Re-stage any modified files with `git add`.
   - Re-run `pre-commit run --all-files`.
   - Repeat up to 5 times. If still failing after 5 attempts, escalate to the user with the failure details.
4. When pre-commit passes, proceed.

### Step 9: Commit & Push

1. Craft a concise commit message in imperative mood (per coding standards). Example: "Add risk scoring engine for requirement prioritization"
2. NEVER include Co-Authored-By, "Generated with Claude Code", or any Claude/AI attribution in commit messages.
3. `git commit -m "<message>"`
3. `git push -u origin <branch>`

---

## Phase D: Ship

### Step 10: Create PR

1. Check if a PR already exists for this branch: `gh pr list --head <branch> --json number,url`
2. If no PR exists, create one:
   ```
   gh pr create --base dev --title "<concise title>" --body "<description with requirement reference>"
   ```
3. Note the PR number and URL.

### Step 11: CI Monitor

1. Find the latest workflow run: `gh run list --branch <branch> --limit 1 --json status,conclusion,databaseId`
2. If the run is in progress, watch it: `gh run watch <id>`
3. If it failed:
   - Get failed logs: `gh run view <id> --log-failed`
   - Diagnose and fix the issue.
   - `git add`, `git commit`, `git push`.
   - Go back to step 1 of this phase.
4. If it succeeded, proceed.

### Step 12: SonarCloud

1. Wait 60 seconds for SonarCloud analysis to propagate.
2. Use `get_project_quality_gate_status` with project key `Brad-Edwards_aptl` to check the quality gate.
3. Use `search_sonar_issues_in_projects` to find new issues on the current branch.
4. If issues found:
   - Fix them.
   - `git add`, `git commit`, `git push`.
   - Re-run Step 11 (CI Monitor).
5. If clean, proceed.

### Step 13: Cross-Model Review (Codex)

Run the OpenAI Codex CLI review against the branch:

`Bash(codex review --base dev)`

### Step 14: Code Review

**CRITICAL: You MUST use the Skill tool to invoke the built-in review skill.**

1. Merge dev into the current branch: `git fetch origin dev && git merge origin/dev`
2. If there are merge conflicts, resolve them, commit, and push.
3. Call the Skill tool with `skill="review"` to invoke the real built-in code review.
4. After the review completes, fix ALL issues it identified.
   - Same rules as Step 13: fix everything, defer nothing.
5. After fixing, re-read all findings and confirm each one was addressed.

### Step 15: Security Review

**CRITICAL: You MUST use the Skill tool to invoke the built-in security-review skill.**

1. Call the Skill tool with `skill="security-review"` to invoke the real built-in security review.
2. After the review completes, fix ALL issues it identified.
   - Same rules as Step 14: fix everything, defer nothing.
3. After fixing, confirm all findings were addressed.

### Step 16: Test Quality Review

**CRITICAL: You MUST use the Skill tool to invoke the review-tests skill.**

1. Call the Skill tool with `skill="review-tests"` to invoke the test quality review.
2. After the review completes, fix ALL critical issues it identified.
   - Rewrite tests that provide false assurance. Do not defer critical findings.
3. Warning-level findings: fix unless doing so significantly increases scope.
4. After fixing, confirm all critical findings were addressed.

### Step 17: Final Commit & CI

If ANY fixes were made in Steps 13-16:
1. `git add` all changed files.
2. `git commit -m "Fix review findings"`
3. `git push`
4. Re-run Step 11 (CI Monitor).
5. Re-run Step 12 (SonarCloud).

### Step 18: Report (DO NOT MERGE)

**You MUST NOT merge the PR. You MUST NOT run `gh pr merge`. The user reviews and merges.**

Provide a final summary:
- What was implemented (requirement title and UID)
- Files created or modified
- Review findings and fixes (if any)
- Security review findings and fixes (if any)
- Test quality review findings and fixes (if any)
- Confirmation: CI green, SonarCloud passed, PR ready for user review
- PR URL
