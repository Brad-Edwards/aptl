---
name: implement
description: Assess and implement a Ground Control requirement, ensuring GitHub issue and traceability links exist
argument-hint: <requirement-uid>
disable-model-invocation: true
---

# Implement Requirement: $ARGUMENTS

## Step 1: Fetch Requirement and Ensure GitHub Issue Exists

1. Enter plan mode.

2. Use the `gc_get_requirement` MCP tool with uid `GC-$ARGUMENTS` to fetch the requirement details. Note the requirement's UUID, title, statement, status, and wave.

3. Use the `gc_get_traceability` MCP tool with the requirement's UUID to check for existing traceability links. Look for a link with artifact_type `GITHUB_ISSUE`.

4. If NO GitHub issue link exists:
   - Use the `gc_create_github_issue` MCP tool with uid `$ARGUMENTS` to create a GitHub issue and auto-link it.

5. If a GitHub issue link DOES exist, note the issue number from the artifact_identifier.

6. Run `gh issue develop <issue-number> --checkout --base dev` to switch to the issue branch.

## Step 2: Read the GitHub Issue

Run `gh issue view <issue-number>` to read the full issue details including description, labels, and comments.

## Step 3: Assess Codebase Coverage

Explore the codebase to determine whether the requirement described in the issue is already satisfied by existing code:
- Search for relevant classes, methods, tests, and configurations
- Check if the described behavior already exists
- Review any existing traceability links (IMPLEMENTS, TESTS) from Step 1

## Step 4: Plan or Report

- **If the requirement is NOT yet met**: Plan the implementation. Identify which files need to be created or modified, what tests to write, and what approach to take. Enter plan mode.
- Your plans must respect the coding standards and classification levels in ADR-012.
- Plans must include updating the changelog, readme, and docs as appropriate.
- **If the requirement IS already met**: Report that the requirement is satisfied and identify which code satisfies it.

## Step 5: Ensure Traceability Links

After implementation is complete (or if already implemented):
- use the `gc_create_traceability_link` MCP tool to create any missing links:
  - `IMPLEMENTS` links from the requirement to the code files that implement it
  - `TESTS` links from the requirement to the test files that verify it
  - Only create links that don't already exist (check the traceability data from Step 1).
- use the `gc_transition_status` MCP tool to transition the requirement to `ACTIVE` if it was `DRAFT`.

Do not update the Changelog if all you did was operate Ground Control tools.
