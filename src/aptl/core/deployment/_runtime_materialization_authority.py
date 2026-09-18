"""Operator-grant qualification for raw runtime authority."""

from aptl.core.deployment._runtime_materialization_types import (
    RuntimeMaterializationIssue,
    RuntimeMaterializationProfile,
    materialization_issue,
)
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.runtime_authority_policy import RuntimeAuthorityPolicy


def authority_issues(
    realization: DeploymentRealizationSpec,
    *,
    profile: RuntimeMaterializationProfile,
    policy: RuntimeAuthorityPolicy,
) -> list[RuntimeMaterializationIssue]:
    """Return unsupported raw-daemon authority admissions."""

    issues: list[RuntimeMaterializationIssue] = []
    for admission in realization.docker_authority_admissions:
        if profile.containment_evidence is None:
            issues.append(
                materialization_issue(
                    admission.node_address,
                    "runtime.orchestration_authorities",
                    profile,
                    "raw daemon authority requires an isolated scenario-exclusive daemon",
                )
            )
            continue
        grant = policy.grant_for(
            realization.pack_identity,
            component_address=admission.node_address,
            authority_id=admission.authority_id,
            endpoint_source=admission.endpoint_source,
            image_template_ids=admission.image_template_ids,
        )
        if grant is None:
            issues.append(
                materialization_issue(
                    admission.node_address,
                    "runtime.orchestration_authorities",
                    profile,
                    "no exact immutable-pack operator grant authorizes the selected endpoint",
                )
            )
    return issues
