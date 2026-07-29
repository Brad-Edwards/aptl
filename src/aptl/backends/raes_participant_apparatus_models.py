"""Typed products of the bounded participant apparatus."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from raes_contracts.contracts import (
    ParticipantDecisionSurfaceSelectionV2Model,
    ParticipantDecisionSurfaceV2Model,
    ParticipantImplementationManifestModel,
    ParticipantImplementationSelectionModel,
)


@dataclass(frozen=True)
class ParticipantApparatus:
    """One exact installed-agent implementation selected for a participant."""

    implementation_selection_ref: str
    manifest_ref: str
    manifest: ParticipantImplementationManifestModel
    selection: ParticipantImplementationSelectionModel
    provider: str
    model: str | None


@dataclass(frozen=True)
class ParticipantDecisionTurn:
    """Trusted products of one RAES v2 projection and delivery."""

    behavior_specification_address: str
    observation_boundary_address: str
    surface: ParticipantDecisionSurfaceV2Model
    rendered_context: tuple[Mapping[str, object], ...]
    observation_history: tuple[Mapping[str, object], ...]
    candidates: tuple[ParticipantDecisionSurfaceSelectionV2Model, ...]
    apparatus: ParticipantApparatus


def reference_token(value: str) -> str:
    """Normalize a contract address for use inside a reference."""

    return value.replace(":", "-").replace(".", "-")
