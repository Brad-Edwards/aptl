# ADR-032: Conversation Surface Hardening

## Status

accepted

## Date

2026-05-17

## Context

The repository's issue, pull-request, and discussion surfaces accept
unstructured text from arbitrary authors. That text is consumed both by
human maintainers and by agent-assisted workflows that read historical
threads as context when responding to current tasks. Unrestricted
authorship on these surfaces is a path for external input to influence
those downstream consumers.

The non-functional security requirement is that input on these surfaces
originates only from vetted authors. The mechanism, scope, and lifetime
of that restriction are operational concerns and are deliberately not
recorded in this ADR or in the tracking issue.

## Decision

Issue, pull-request, and discussion authorship on this repository is
restricted to vetted authors. Past content authored outside the vetted
set is reviewed and curated where appropriate.

## Consequences

- External authors cannot open or comment on issues, pull requests, or
  discussions on this repository without prior vetting.
- Maintainers and approved contributors are unaffected.
- Existing historical content is preserved except where curation
  required its removal.
- Operational details of the mechanism live outside the repository and
  are not subject to ADR change-control.
