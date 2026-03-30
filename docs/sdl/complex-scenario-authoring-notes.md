# Complex Scenario Authoring Notes

This file is a persistent issue log for the large SDL example scenarios
added in this branch. It exists specifically so scenario-authoring
friction does not disappear into chat context.

## Notes

- Initial design goal: author scenarios from explicit design briefs first,
  then encode them into SDL examples and tests.
- Real authoring friction: enum-backed fields remain concretely typed in
  practice. Attempting to parameterize `accounts.*.password_strength` with
  `${var}` fails model validation, so the larger examples had to keep
  those values literal. This matches the current docs, but it is a real
  limitation when trying to make scenario posture tunable.
- Objectives resolve against named scenario elements, but not directly
  against service bindings or ACL rules. In practice, that meant the
  examples had to make important trust or control paths explicit as
  `features` or `relationships` so objectives could target them cleanly.
- Release and recovery stories with branch points still need to be
  flattened into `stories` / `scripts` / `events` plus objective
  `depends_on`. The examples can express sequencing and windows, but not
  true CACAO-style alternate branches or parallel step graphs.
