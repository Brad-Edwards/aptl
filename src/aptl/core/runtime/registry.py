"""Registry for runtime targets."""

from dataclasses import dataclass
from typing import Any, Callable

from aptl.core.runtime.capabilities import BackendManifest
from aptl.core.runtime.protocols import Evaluator, Orchestrator, Provisioner


def _validate_runtime_target_shape(
    *,
    manifest: BackendManifest | None,
    provisioner: Provisioner | None,
    orchestrator: Orchestrator | None,
    evaluator: Evaluator | None,
) -> None:
    if manifest is None:
        raise ValueError("RuntimeTarget requires an explicit manifest.")
    if provisioner is None:
        raise ValueError("RuntimeTarget requires a provisioner.")
    if manifest.has_orchestrator != (orchestrator is not None):
        raise ValueError(
            "registry.target-shape-mismatch: orchestrator presence does not "
            "match the manifest."
        )
    if manifest.has_evaluator != (evaluator is not None):
        raise ValueError(
            "registry.target-shape-mismatch: evaluator presence does not match "
            "the manifest."
        )


@dataclass(frozen=True)
class RuntimeTarget:
    """A fully configured runtime target."""

    name: str
    manifest: BackendManifest
    provisioner: Provisioner
    orchestrator: Orchestrator | None = None
    evaluator: Evaluator | None = None

    def __post_init__(self) -> None:
        _validate_runtime_target_shape(
            manifest=self.manifest,
            provisioner=self.provisioner,
            orchestrator=self.orchestrator,
            evaluator=self.evaluator,
        )


@dataclass(frozen=True)
class RuntimeTargetComponents:
    """Instantiated runtime target components without a manifest."""

    provisioner: Provisioner
    orchestrator: Orchestrator | None = None
    evaluator: Evaluator | None = None


@dataclass(frozen=True)
class RuntimeTargetDescriptor:
    """Factories for manifest introspection and target creation."""

    name: str
    manifest_factory: Callable[..., BackendManifest]
    components_factory: Callable[..., RuntimeTargetComponents]


class BackendRegistry:
    """Registry of runtime target descriptors."""

    def __init__(self) -> None:
        self._descriptors: dict[str, RuntimeTargetDescriptor] = {}

    def register(
        self,
        name: str,
        manifest_factory: Callable[..., BackendManifest],
        components_factory: Callable[..., RuntimeTargetComponents],
    ) -> None:
        self._descriptors[name] = RuntimeTargetDescriptor(
            name=name,
            manifest_factory=manifest_factory,
            components_factory=components_factory,
        )

    def describe(self, name: str) -> RuntimeTargetDescriptor:
        if name not in self._descriptors:
            registered = sorted(self._descriptors)
            raise KeyError(
                f"Unknown backend '{name}'. Registered backends: {registered}"
            )
        return self._descriptors[name]

    def manifest(self, name: str, **config: Any) -> BackendManifest:
        return self.describe(name).manifest_factory(**config)

    def create(self, name: str, **config: Any) -> RuntimeTarget:
        descriptor = self.describe(name)
        manifest = descriptor.manifest_factory(**config)
        components = descriptor.components_factory(manifest=manifest, **config)

        if hasattr(components, "evaluators"):
            raise ValueError(
                "registry.target-shape-mismatch: legacy evaluator collections are "
                "not supported."
            )

        _validate_runtime_target_shape(
            manifest=manifest,
            provisioner=components.provisioner,
            orchestrator=components.orchestrator,
            evaluator=components.evaluator,
        )

        return RuntimeTarget(
            name=name,
            manifest=manifest,
            provisioner=components.provisioner,
            orchestrator=components.orchestrator,
            evaluator=components.evaluator,
        )

    def list_backends(self) -> list[str]:
        return sorted(self._descriptors)

    def is_registered(self, name: str) -> bool:
        return name in self._descriptors
