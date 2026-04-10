---
name: Fix all failures, not just your own
description: Never dismiss test failures or issues as "pre-existing" or "not related to my changes" - fix them all
type: feedback
---

Fix ALL test failures encountered, not just ones caused by your changes. Do not dismiss failures as "pre-existing" or "unrelated." Show ownership of the entire codebase.

**Why:** The user views "pre-existing" as a lazy excuse. The CLAUDE.md also explicitly states: "Skipping tests or problems as 'pre-existing' is not a valid excuse."

**How to apply:** When running tests, if any fail, investigate and fix them regardless of origin. Do not move on until the suite is green.
