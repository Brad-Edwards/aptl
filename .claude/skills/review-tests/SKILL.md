---
name: review-tests
description: Review test files for quality — catches shallow coverage tests, integration-as-unit, inline mock abuse, missing parameterization, and tests that can't detect regressions.
---

# Test Quality Review

You are reviewing test files changed in the current branch. Your job is to identify **tests that provide false assurance** — tests that pass but would still pass if the implementation were broken.

## How to Find Changed Test Files

```bash
git diff --name-only origin/dev...HEAD | grep -iE '(test_|_test\.|tests/|Test\.)'
```

If the base branch is `main` instead of `dev`, adjust accordingly. Read every changed test file. For each, also read the source file it tests so you understand what behavior should be verified.

## What to Flag

### Critical (must fix)

1. **Assertion-free tests** — tests that call code but never assert on the result. A test that only checks "no exception was raised" is not a test.

2. **Mock-only assertions** — tests where the only assertion is that a mock was called. This verifies wiring, not behavior. The test must also assert on the **return value, side effect, or state change** produced by the code under test.

3. **Integration masquerading as unit** — tests that hit a real database, make real HTTP calls, touch the filesystem, or spawn subprocesses without being explicitly marked as integration tests. Unit tests must be isolated.

4. **Per-test resource setup** — creating a database, connection pool, or heavy resource inside each test method instead of using shared fixtures or setup methods. This causes OOM at scale.

5. **Mocking language/framework internals** — mocking subprocess, os.path, datetime.now, or equivalent framework internals. If you need to mock these, the code under test needs restructuring, not more mocks.

6. **Tests that can't detect regressions** — if you could replace the function under test with a no-op and the test would still pass, the test is worthless. Check: does the test assert on something that **only the correct implementation** would produce?

### Warnings (should fix)

7. **Inline mock/stub abuse** — excessive mock/stub/spy instantiation inside a single test method instead of shared fixtures or setup.

8. **Missing parameterization** — multiple near-identical test methods that differ only in input/expected output. These should use parameterized tests.

9. **Overly broad exception catching** — catching generic Exception types in assertions instead of the specific exception.

10. **No negative test cases** — only happy-path tests with no error/edge case coverage.

## How to Review

For each test file:

1. Read the test file.
2. Read the source file it tests.
3. For each test method, answer: "If I broke the implementation, would this test catch it?"
4. If the answer is no, flag it.

## Output Format

For each finding:
```
**[CRITICAL/WARNING] test_file::TestClass::test_method**
Problem: <what's wrong>
Why it matters: <what regression this would miss>
Fix: <specific fix, not vague advice>
```

## After Review

If you found CRITICAL issues: fix them all before proceeding. Rewrite the tests to actually verify behavior.

If you found only WARNINGS: fix them unless doing so would significantly increase scope. Note any deferred warnings in the PR description.

If the tests are solid: report "Test quality review: no issues found" and proceed.
