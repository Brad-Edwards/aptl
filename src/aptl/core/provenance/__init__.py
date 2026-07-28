"""Run-scoped apparatus and detection-content provenance (REP-003 / issue #452).

This package records the realized APTL instrument at a run's seal boundary:
which scenario, apparatus, participant implementation, images, rules,
collectors, and relevant configuration were actually used.

The design boundaries are fixed by
``docs/architecture/rep-003-run-scoped-provenance-preflight.md``:

* Two deliberately separate namespaces — portable RAES-owned apparatus and
  experiment identity, versus APTL backend-owned realized-instrument
  provenance. This package composes owner-native payloads; it never defines a
  second apparatus, experiment, or capability schema.
* A narrow, trusted, capability-declared provider seam (:mod:`.registry`) with
  bounded typed outcomes (:mod:`.outcomes`) — not one monolithic collector and
  not a general plugin framework.
* Allowlist-first collection. A provider reads only explicit owner-declared
  non-secret sources; redaction is drift detection, never authorization to
  ingest a prohibited source.
* Stable, explainable identity (:mod:`.identity`) — per-leaf logical roles
  folded into families over sorted canonical sequences, so one changed rule,
  image, or setting moves its own leaf plus its ancestors and nothing else.

The record this package publishes is *ready-to-seal* provenance. Issue #444
owns signing and the sealed archive state; issue #472 owns which limitations
are fatal. Nothing here claims a run is sealed.
"""
