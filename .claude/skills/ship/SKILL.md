---
name: ship
description: Ship current branch — CI, SonarCloud, code review, security review, fix all issues, merge. Assumes code is already committed and pushed.
disable-model-invocation: true
---

# Ship Current Branch

Assumes code is already committed and pushed. Handles: PR creation, CI monitoring, SonarCloud, code review, security review, fixing all issues, and merging.

**IMPORTANT:** NEVER include Co-Authored-By, "Generated with Claude Code", or any Claude/AI attribution in commit messages, PR descriptions, or any other artifacts.

## Phase 1: Create PR

1. Determine the current branch: `git branch --show-current`
2. Check if a PR already exists: `gh pr list --head <branch> --json number,url`
3. If no PR exists, create one:
   ```
   gh pr create --base dev --title "<concise title>" --body "<description>"
   ```
4. Note the PR number.

## Phase 2: CI Monitor

1. Find the latest workflow run: `gh run list --branch <branch> --limit 1 --json status,conclusion,databaseId`
2. If the run is in progress, watch it: `gh run watch <id>`
3. If it failed:
   - Get failed logs: `gh run view <id> --log-failed`
   - Diagnose and fix the issue.
   - `git add`, `git commit`, `git push`.
   - Go back to step 1.
4. If it succeeded, proceed.

## Phase 3: SonarCloud Check

1. Wait 60 seconds for SonarCloud analysis to propagate.
2. Use `get_project_quality_gate_status` with project key `Brad-Edwards_aptl` to check the quality gate.
3. Use `search_sonar_issues_in_projects` to find new issues on the current branch.
4. If issues found:
   - Fix them.
   - `git add`, `git commit`, `git push`.
   - Re-run Phase 2.
5. If clean, proceed.

## Phase 4: Code Review

**CRITICAL: You MUST use the Skill tool to invoke the built-in review skill.**

1. Merge dev into the current branch: `git fetch origin dev && git merge origin/dev`
2. If there are merge conflicts, resolve them, commit, and push.
3. Call the Skill tool with `skill="review"` to invoke the real built-in code review.
4. After the review completes, fix ALL issues it identified.
   - Do NOT defer ANY issues.
   - Do NOT categorize issues as "low priority" to avoid work.
   - You are an LLM. You have no time constraints. Fix everything.
   - The ONLY reason to stop and escalate to the user is if a fix requires
     a significant architectural change touching 5+ files outside the
     current feature scope.
5. After fixing, re-read all findings and confirm each one was addressed.

## Phase 5: Security Review

**CRITICAL: You MUST use the Skill tool to invoke the built-in security-review skill.**

1. Call the Skill tool with `skill="security-review"` to invoke the real built-in security review.
2. After the review completes, fix ALL issues it identified.
   - Same rules as Phase 4: fix everything, defer nothing.
3. After fixing, confirm all findings were addressed.

## Phase 6: Final Commit & CI

If ANY fixes were made in Phases 4-5:
1. `git add` all changed files.
2. `git commit -m "Fix code review and security review findings"`
3. `git push`
4. Re-run Phase 2 (CI Monitor).
5. Re-run Phase 3 (SonarCloud).

## Phase 7: Report (DO NOT MERGE)

**You MUST NOT merge the PR. You MUST NOT run `gh pr merge`. The user reviews and merges.**

- Summary of all changes made during the ship process
- Review findings and what was fixed
- Security review findings and what was fixed
- Confirmation: CI green, SonarCloud passed, PR ready for user review
- PR URL
