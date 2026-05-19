"""APTL backend implementations.

ACES backend adapter (`aces`) declaring conformance to the ACES
``provisioning-only`` profile. The provisioner wraps APTL's
``DeploymentBackend`` and translates ACES ``ApplyResult`` shapes to
``LabResult`` envelopes at the boundary (per ADR-035).
"""
