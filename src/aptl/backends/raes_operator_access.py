"""Admit the operator interactive access a scenario declares.

RAES compiles ``agents.<agent>.interactive_access`` into the participant model,
not the provisioning plan, so the deployment backend never saw it: TechVault
declared SSH access for its red and blue operators and nothing made either
reachable from the operator's host (issue #1006).

This reads the declaration at admission, beside the other scenario-derived
backend decisions, and splits it into access the backend can realize and access
it cannot. An unrealizable declaration is refused before anything is started —
declared access is part of the environment, not a best effort.
"""

from __future__ import annotations

from dataclasses import dataclass

from aptl.core.deployment._operator_access import realizable_access
from aptl.core.deployment.realization import DeploymentOperatorAccess


@dataclass(frozen=True)
class OperatorAccessDecision(object):
    """Declared operator access, split by whether the backend can realize it."""

    accesses: tuple[DeploymentOperatorAccess, ...] = ()
    unrealizable: tuple[DeploymentOperatorAccess, ...] = ()


def operator_access_decision(scenario: object) -> OperatorAccessDecision:
    """Collect every declared interactive access from a parsed scenario."""

    accesses: list[DeploymentOperatorAccess] = []
    unrealizable: list[DeploymentOperatorAccess] = []
    agents = getattr(scenario, "agents", None) or {}
    for agent_name, agent in sorted(agents.items()):
        declared = getattr(agent, "interactive_access", None) or {}
        for access_id, access in sorted(declared.items()):
            channel = getattr(access, "channel", "")
            record = DeploymentOperatorAccess(
                access_id=str(access_id),
                agent=str(agent_name),
                target_node=str(getattr(access, "target_ref", "") or ""),
                channel=str(getattr(channel, "value", channel) or ""),
            )
            if realizable_access(record.target_node, record.channel):
                accesses.append(record)
            else:
                unrealizable.append(record)
    return OperatorAccessDecision(
        accesses=tuple(accesses), unrealizable=tuple(unrealizable)
    )
