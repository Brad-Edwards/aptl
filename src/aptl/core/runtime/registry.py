"""Registry for runtime targets."""

from inspect import Signature, signature
from dataclasses import dataclass
from typing import Any, Callable

from aptl.core.runtime.capabilities import BackendManifest
from aptl.core.runtime.protocols import Evaluator, Orchestrator, Provisioner


def _require_invokable_method(
    component: object | None,
    *,
    label: str,
    method_name: str,
    invocation_args: tuple[object, ...],
) -> None:
    if component is None:
        return
    method = getattr(component, method_name, None)
    if not callable(method):
        raise ValueError(
            "registry.target-contract-mismatch: "
            f"{label} is missing callable method '{method_name}'."
        )
    try:
        method_signature = signature(method)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "registry.target-contract-mismatch: "
            f"{label}.{method_name} has a non-inspectable signature."
        ) from exc
    try:
        method_signature.bind(*invocation_args)
    except TypeError as exc:
        rendered_signature = _render_signature(method_signature)
        raise ValueError(
            "registry.target-contract-mismatch: "
            f"{label}.{method_name}{rendered_signature} is incompatible with "
            f"the runtime call shape for {label}.{method_name}."
        ) from exc


def _render_signature(method_signature: Signature) -> str:
    return str(method_signature)


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
    sample_plan = object()
    sample_snapshot = object()
    _require_invokable_method(
        provisioner,
        label="provisioner",
        method_name="validate",
        invocation_args=(sample_plan,),
    )
    _require_invokable_method(
        provisioner,
        label="provisioner",
        method_name="apply",
        invocation_args=(sample_plan, sample_snapshot),
    )
    _require_invokable_method(
        orchestrator,
        label="orchestrator",
        method_name="start",
        invocation_args=(sample_plan, sample_snapshot),
    )
    _require_invokable_method(
        orchestrator,
        label="orchestrator",
        method_name="status",
        invocation_args=(),
    )
    _require_invokable_method(
        orchestrator,
        label="orchestrator",
        method_name="results",
        invocation_args=(),
    )
    _require_invokable_method(
        orchestrator,
        label="orchestrator",
        method_name="history",
        invocation_args=(),
    )
    _require_invokable_method(
        orchestrator,
        label="orchestrator",
        method_name="stop",
        invocation_args=(sample_snapshot,),
    )
    _require_invokable_method(
        evaluator,
        label="evaluator",
        method_name="start",
        invocation_args=(sample_plan, sample_snapshot),
    )
    _require_invokable_method(
        evaluator,
        label="evaluator",
        method_name="status",
        invocation_args=(),
    )
    _require_invokable_method(
        evaluator,
        label="evaluator",
        method_name="results",
        invocation_args=(),
    )
    _require_invokable_method(
        evaluator,
        label="evaluator",
        method_name="stop",
        invocation_args=(sample_snapshot,),
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
        if name in self._descriptors:
            raise ValueError(
                f"Backend '{name}' is already registered and cannot be replaced."
            )
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
