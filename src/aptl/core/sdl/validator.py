"""Semantic validation for SDL scenarios.

Goes beyond Pydantic structural checks to enforce cross-reference
integrity, dependency cycle detection, IP/CIDR consistency, and
domain-specific rules. Collects all errors rather than failing on
the first one.

The validation passes are organized into concern-specific mixins
(infrastructure, orchestration, objectives, workflows, and the named-reference
index); ``SemanticValidator`` composes them and drives the pass ordering.
"""

from aptl.core.sdl._errors import SDLValidationError
from aptl.core.sdl.nodes import NodeType
from aptl.core.sdl.scenario import Scenario
from aptl.core.sdl.validator_base import _topological_sort
from aptl.core.sdl.validator_infrastructure import _InfrastructureMixin
from aptl.core.sdl.validator_objectives import _ObjectiveMixin
from aptl.core.sdl.validator_orchestration import _OrchestrationMixin
from aptl.core.sdl.validator_workflows import _WorkflowMixin

__all__ = ["SemanticValidator", "_topological_sort"]


class SemanticValidator(
    _InfrastructureMixin,
    _OrchestrationMixin,
    _ObjectiveMixin,
    _WorkflowMixin,
):
    """Validates a Scenario beyond structural Pydantic checks.

    Call ``validate()`` to run all passes. Raises ``SDLValidationError``
    with all collected errors if any pass fails.
    """

    def __init__(self, scenario: Scenario) -> None:
        """Initialize the validator for ``scenario``."""
        super().__init__(scenario)

    def validate(self) -> None:
        """Run all validation passes and raise on errors."""
        self._errors = []
        self._warnings = []

        # OCR passes
        self._verify_nodes()
        self._verify_infrastructure()
        self._verify_features()
        self._verify_conditions()
        self._verify_vulnerabilities()
        self._verify_metrics()
        self._verify_evaluations()
        self._verify_tlos()
        self._verify_goals()
        self._verify_entities()
        self._verify_injects()
        self._verify_events()
        self._verify_scripts()
        self._verify_stories()
        self._verify_roles()

        # New section passes
        self._verify_content()
        self._verify_accounts()
        self._verify_relationships()
        self._verify_agents()
        self._verify_objectives()
        self._verify_workflows()
        self._verify_variables()
        self._collect_advisories()

        if self._errors:
            raise SDLValidationError(self._errors)

    @property
    def warnings(self) -> list[str]:
        """Return non-fatal advisories collected during validation."""
        return list(self._warnings)

    def _collect_advisories(self) -> None:
        """Run advisory (non-fatal) passes."""
        self._warn_missing_vm_resources()

    def _warn_missing_vm_resources(self) -> None:
        """Warn for VM nodes that omit a 'resources' block."""
        for name, node in self._s.nodes.items():
            if node.type != NodeType.VM:
                continue
            if node.resources is None:
                self._warn(
                    f"Node '{name}' is a VM without 'resources'. This is "
                    "valid SDL, but may be undeployable unless the backend "
                    "supplies defaults."
                )
