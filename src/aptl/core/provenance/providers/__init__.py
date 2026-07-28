"""The trusted built-in provenance providers (REP-003 / issue #452).

Each module here supplies exactly one declared source and reuses that source's
canonical owner — the RAES manifest serializers, the admitted trial plan, the
participant apparatus builder, the deployment backend, the snapshot owner —
rather than re-deriving facts or reaching for Docker, Compose, SSH, curl, or a
shell.

Adding the next built-in source costs one registration, one narrow adapter
here, and its conformance tests. It must not require editing the aggregate
record builder, the run controller, RAES DTOs, the storage layout, or the
exporter.
"""
