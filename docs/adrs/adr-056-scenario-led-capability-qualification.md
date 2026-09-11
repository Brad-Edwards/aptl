# ADR-056: Scenario-Led Capability Qualification

## Status

proposed

## Date

2026-09-05

## Context

The backend already publishes a broad manifest and a realization envelope.
The static conformance gate uses a no-start backend. Existing issues identify
ignored OS versions, undeclared init state, runtime limits and post-admission
mutations. A syntactically valid declaration therefore does not establish that
every advertised effect is realized correctly.

The product needs a small useful entry profile and room to grow through fully
adopted scenarios. It cannot promise support from a feature wishlist or treat
one successful TechVault startup as proof of arbitrary compositions.

## Proposed decision

Maintain a versioned capability ledger owned by
[LilRAE #6](https://github.com/OpenRAE/lilrae/issues/6), with independent
conformance delivery under [LilRAE #4](https://github.com/OpenRAE/lilrae/issues/4).
For each exact claim record:

- The released scenario/pack digest and requirement that needs it.
- RAES contract/profile version and backend implementation/configuration.
- Supported host, runtime, architecture and resource envelope.
- Pre-mutation admission test, including an unsupported/unauthorized case.
- Actual effect, independent native readback and portable evidence mapping.
- Failure, interruption, rollback, reset and teardown behavior.
- Limitations, ownership and qualification evidence identity.

A scenario is adopted only when its declared content, dependencies, runtime
authority, service behavior, participant paths and cleanup are qualified from
normal acquired artifacts. A partial implementation is recorded as such.
Claims outside the qualified envelope fail explicitly; remove or narrow an
unsupported claim rather than emitting a substitute and calling it exact.

Growing the envelope requires a concrete scenario to force the need. Extend
the smallest reusable mechanism, contribute a portable contract upstream when
needed, add positive and negative live evidence, then update the manifest.
Do not require a universal materializer, all infrastructure kits, or backend
parity with BigRAE before the personal backend becomes useful.

Distinguish four evidence levels: static/schema checks; adapter integration;
native realization and readback; released user journey. Name the level in each
report. Mock-backed conformance is useful protocol evidence and never native
realization proof. Structural parity, scenario semantic verification and
scientific validity are separate claims.

The tiny quickstart and full TechVault are separate qualification tracks over
one backend. Unsupported advanced functionality must not prevent an honestly
narrow tiny profile from shipping. Full TechVault adoption retains its stronger
parity criteria and cannot be replaced by an observability-only demonstration.

## Existing ADR disposition

Clarify ADR-035, ADR-044, ADR-046, ADR-047, ADR-048, ADR-050 and ADR-051.
Their useful mechanisms remain. This decision adds the release evidence rule
and replaces any interpretation that a static pass certifies the runtime.

## Consequences and verification

- Existing #909 and #915–#918 are conformance blockers for affected claims.
- #877 separates structural and semantic gates; #878/#879 provide the installed
  verifier path; #870 and #685 prove full TechVault on claimed platforms.
- #883–#887 may be adopted separately. Their mere catalog presence is not
  support evidence. #953 must be re-scoped because admission reuse has landed.
- LilRAE #10 owns the tiny released journey. Paired-backend research stays in
  LilRAE #11 and must not compare APTL and LilRAE as independent backends.
- Accepted historical evidence is retained with its original version scope.
  A new backend or pack version cannot inherit a claim without compatibility
  evidence appropriate to the change.
