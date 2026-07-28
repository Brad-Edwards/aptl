"""Certificate-bundle host roots resolve per producer, not per generator kind.

RAES's `GeneratedArtifactKind` vocabulary is deliberately small — `certificate_bundle`
and `rendered_config` — so several distinct producers necessarily share one kind.
Mapping the host root off the kind alone therefore sent every bundle to the Wazuh
indexer certificate directory, which silently broke any bundle produced elsewhere.

This was caught by a real `aptl lab start`, not by the unit suite: the static gate
never runs generation, so the misdirected root only surfaced as
"Generated artifact ... is missing declared output" during apply.
"""

from __future__ import annotations

from pathlib import Path

from aptl.core.deployment._compose_stateful_model import artifact_source_path
from aptl.core.deployment.realization import DeploymentGeneratedArtifactRealization

_PROJECT = Path("/project")


def _artifact(provenance: str, generator: str = "certificate_bundle"):
    return DeploymentGeneratedArtifactRealization(
        address="provision.generated-artifact.x",
        name="x",
        generator=generator,
        lifecycle="reuse_valid",
        provenance=provenance,
        outputs=(),
        consumers=(),
    )


def test_soc_ca_resolves_to_its_own_producer_directory():
    """The lab-managed SOC CA is written by soc_ca.py into config/soc_certs."""

    path = artifact_source_path(_PROJECT, _artifact("src/aptl/core/soc_ca.py"))

    assert path == _PROJECT.resolve() / "config/soc_certs"


def test_wazuh_bundles_keep_the_indexer_certificate_root():
    """The pre-existing bundles are unaffected by provenance-based resolution."""

    path = artifact_source_path(_PROJECT, _artifact("config/certs.yml"))

    assert path == _PROJECT.resolve() / "config/wazuh_indexer_ssl_certs"


def test_unmapped_provenance_falls_back_to_the_indexer_root():
    """An unknown producer keeps the historical behaviour rather than failing."""

    path = artifact_source_path(_PROJECT, _artifact("config/something-new.yml"))

    assert path == _PROJECT.resolve() / "config/wazuh_indexer_ssl_certs"


def test_rendered_config_is_unaffected_by_certificate_root_mapping():
    """Only certificate bundles consult the provenance map."""

    path = artifact_source_path(
        _PROJECT, _artifact("src/aptl/core/soc_ca.py", generator="rendered_config")
    )

    assert path != _PROJECT.resolve() / "config/soc_certs"


def test_admission_and_resolution_share_one_producer_allowlist():
    """A producer cannot be accepted without a root, or get a root unaccepted.

    Admission previously hardcoded a single acceptable provenance while
    resolution keyed off the generator kind. Keeping both on one table means a
    new producer is either fully known or fully rejected, never half-wired.
    """

    from aptl.core.deployment._compose_stateful_constants import (
        CERTIFICATE_ROOT_BY_PROVENANCE,
    )

    assert "config/certs.yml" in CERTIFICATE_ROOT_BY_PROVENANCE
    assert "src/aptl/core/soc_ca.py" in CERTIFICATE_ROOT_BY_PROVENANCE
    for provenance, root in CERTIFICATE_ROOT_BY_PROVENANCE.items():
        assert artifact_source_path(_PROJECT, _artifact(provenance)) == (
            _PROJECT.resolve() / root
        )


def test_unknown_producer_is_refused_by_admission():
    """An unlisted provenance fails admission rather than defaulting silently."""

    from aptl.core.deployment._compose_stateful_graph import _artifact_errors
    from aptl.core.deployment.realization import DeploymentRealizationSpec

    spec = DeploymentRealizationSpec(
        profiles=(),
        nodes=(),
        networks=(),
        generated_artifacts=(_artifact("config/attacker-supplied.yml"),),
    )

    assert any("unsupported provenance" in e for e in _artifact_errors(spec))
