---
name: stage
description: Stage files, run pre-commit, fix failures, loop until clean
disable-model-invocation: true
---

# Stage Changes

## Step 1: Identify Changed Files

1. Run `git status` to see all changed and untracked files.
2. Exclude from staging: .env files, credentials, secrets, large binaries.

## Step 2: Stage Files

1. `git add` all relevant changed files.

## Step 3: Pre-commit Loop

Run up to 5 iterations:

1. Run `pre-commit run --all-files`.
2. If it passes, proceed to Step 4.
3. If it fails:
   - Read the failure output.
   - Fix the issues.
   - Re-stage any modified files with `git add`.
   - Go back to step 1.
4. If still failing after 5 attempts, report the failure details to the user and stop.

## Step 4: Report

- List what is staged: `git diff --cached --name-only`
- Confirm pre-commit passes.
- "All files staged and pre-commit clean. Ready for commit."
