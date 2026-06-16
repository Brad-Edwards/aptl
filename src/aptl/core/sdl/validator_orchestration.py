"""Validation passes for orchestration and supporting sections.

Covers features, conditions, vulnerabilities, metrics, evaluations, TLOs,
goals, entities, injects, events, scripts, stories, and the variable-reference
sweep over the whole scenario tree.
"""

from collections.abc import Iterable

from pydantic import BaseModel

from aptl.core.sdl._base import extract_variable_name
from aptl.core.sdl.entities import Entity, flatten_entities
from aptl.core.sdl.orchestration import Event, Inject
from aptl.core.sdl.scenario import Scenario
from aptl.core.sdl.scoring import MetricType
from aptl.core.sdl.validator_base import _ValidatorCore, _topological_sort


class _OrchestrationMixin(_ValidatorCore):
    """Feature/metric/entity/event/variable validation passes."""

    def _verify_missing_refs(
        self,
        owner_label: str,
        refs: Iterable[str],
        defined: object,
        ref_noun: str,
    ) -> None:
        """Emit an error for each resolved ``ref`` absent from ``defined``."""
        for ref in refs:
            if self._is_unresolved_var(ref):
                continue
            if ref not in defined:  # type: ignore[operator]
                self._err(
                    f"{owner_label} references undefined {ref_noun} '{ref}'"
                )

    def _verify_features(self) -> None:
        """Validate feature vulnerability refs and dependency acyclicity."""
        for name, feat in self._s.features.items():
            self._verify_missing_refs(
                f"Feature '{name}'",
                feat.vulnerabilities,
                self._s.vulnerabilities,
                "vulnerability",
            )

        dep_graph: dict[str, list[str]] = {}
        for name, feat in self._s.features.items():
            dep_graph[name] = []
            for dep in feat.dependencies:
                if self._is_unresolved_var(dep):
                    continue
                if dep not in self._s.features:
                    self._err(
                        f"Feature '{name}' depends on undefined feature '{dep}'"
                    )
                else:
                    dep_graph[name].append(dep)

        if dep_graph and _topological_sort(dep_graph) is None:
            self._err("Feature dependency graph contains a cycle")

    def _verify_conditions(self) -> None:
        """No cross-scenario condition checks; handled by Pydantic."""
        # Individual condition validation is handled by Pydantic model_validator.
        # This pass checks for consistency with the broader scenario.

    def _verify_vulnerabilities(self) -> None:
        """No cross-scenario vulnerability checks; handled by Pydantic."""
        # CWE format validation is handled by the Pydantic field_validator.

    def _verify_metrics(self) -> None:
        """Validate conditional-metric condition refs and uniqueness."""
        used_conditions: set[str] = set()

        for name, metric in self._s.metrics.items():
            if metric.type != MetricType.CONDITIONAL:
                continue
            cond = metric.condition
            if self._is_unresolved_var(cond):
                continue
            if cond and cond not in self._s.conditions:
                self._err(
                    f"Metric '{name}' references undefined condition '{cond}'"
                )
            if cond in used_conditions:
                self._err(
                    f"Condition '{cond}' is referenced by multiple metrics"
                )
            if cond:
                used_conditions.add(cond)

    def _evaluation_metric_max_total(
        self, name: str, metric_names: Iterable[str]
    ) -> tuple[int, bool]:
        """Sum metric max-scores for an evaluation.

        Returns ``(max_total, unknown_max_score)`` where the flag is True when
        any metric contributes an unresolved or non-integer max score.
        """
        max_total = 0
        unknown_max_score = False
        for metric_name in metric_names:
            if self._is_unresolved_var(metric_name):
                unknown_max_score = True
                continue
            if metric_name not in self._s.metrics:
                self._err(
                    f"Evaluation '{name}' references undefined metric "
                    f"'{metric_name}'"
                )
                continue
            metric_max_score = self._s.metrics[metric_name].max_score
            if isinstance(metric_max_score, int):
                max_total += metric_max_score
            else:
                unknown_max_score = True
        return max_total, unknown_max_score

    def _verify_evaluations(self) -> None:
        """Validate evaluation metric refs and min-score feasibility."""
        for name, evaluation in self._s.evaluations.items():
            max_total, unknown_max_score = self._evaluation_metric_max_total(
                name, evaluation.metrics
            )

            if (
                isinstance(evaluation.min_score.absolute, int)
                and not unknown_max_score
                and evaluation.min_score.absolute > max_total
            ):
                self._err(
                    f"Evaluation '{name}' absolute min-score "
                    f"({evaluation.min_score.absolute}) exceeds sum of "
                    f"metric max-scores ({max_total})"
                )

    def _verify_tlos(self) -> None:
        """Validate that each TLO references a defined evaluation."""
        for name, tlo in self._s.tlos.items():
            if self._is_unresolved_var(tlo.evaluation):
                continue
            if tlo.evaluation not in self._s.evaluations:
                self._err(
                    f"TLO '{name}' references undefined evaluation "
                    f"'{tlo.evaluation}'"
                )

    def _verify_goals(self) -> None:
        """Validate that each goal references defined TLOs."""
        for name, goal in self._s.goals.items():
            self._verify_missing_refs(
                f"Goal '{name}'", goal.tlos, self._s.tlos, "TLO"
            )

    def _verify_entity(self, name: str, entity: Entity) -> None:
        """Validate a single entity's TLO, vulnerability and event refs."""
        self._verify_missing_refs(
            f"Entity '{name}'", entity.tlos, self._s.tlos, "TLO"
        )
        self._verify_missing_refs(
            f"Entity '{name}'",
            entity.vulnerabilities,
            self._s.vulnerabilities,
            "vulnerability",
        )
        self._verify_missing_refs(
            f"Entity '{name}'", entity.events, self._s.events, "event"
        )

    def _verify_entities(self) -> None:
        """Validate every flattened entity's references."""
        flat = flatten_entities(self._s.entities)
        for name, entity in flat.items():
            self._verify_entity(name, entity)

    def _verify_inject(self, name: str, inject: Inject, flat_names: set[str]) -> None:
        """Validate one inject's entity endpoints and TLO refs."""
        if (
            inject.from_entity
            and not self._is_unresolved_var(inject.from_entity)
            and inject.from_entity not in flat_names
        ):
            self._err(
                f"Inject '{name}' from_entity '{inject.from_entity}' "
                f"is not a defined entity"
            )
        for to_name in inject.to_entities:
            if self._is_unresolved_var(to_name):
                continue
            if to_name not in flat_names:
                self._err(
                    f"Inject '{name}' to_entity '{to_name}' "
                    f"is not a defined entity"
                )
        self._verify_missing_refs(
            f"Inject '{name}'", inject.tlos, self._s.tlos, "TLO"
        )

    def _verify_injects(self) -> None:
        """Validate every inject's entity and TLO references."""
        flat_names = self._all_entity_names()
        for name, inject in self._s.injects.items():
            self._verify_inject(name, inject, flat_names)

    def _verify_event(self, name: str, event: Event) -> None:
        """Validate one event's condition and inject references."""
        self._verify_missing_refs(
            f"Event '{name}'", event.conditions, self._s.conditions, "condition"
        )
        self._verify_missing_refs(
            f"Event '{name}'", event.injects, self._s.injects, "inject"
        )

    def _verify_events(self) -> None:
        """Validate every event's condition and inject references."""
        for name, event in self._s.events.items():
            self._verify_event(name, event)

    def _verify_scripts(self) -> None:
        """Validate that each script references defined events."""
        for name, script in self._s.scripts.items():
            self._verify_missing_refs(
                f"Script '{name}'", script.events, self._s.events, "event"
            )

    def _verify_stories(self) -> None:
        """Validate that each story references defined scripts."""
        for name, story in self._s.stories.items():
            self._verify_missing_refs(
                f"Story '{name}'", story.scripts, self._s.scripts, "script"
            )

    def _visit_model_variable_refs(
        self, value: BaseModel, path: str, defined: set[str]
    ) -> None:
        """Recurse into each field of a Pydantic model checking refs."""
        for field_name in value.__class__.model_fields:
            if isinstance(value, Scenario) and field_name == "variables":
                continue
            child = getattr(value, field_name)
            child_path = f"{path}.{field_name}" if path else field_name
            self._visit_variable_refs(child, child_path, defined)

    def _visit_variable_refs(
        self, value: object, path: str, defined: set[str]
    ) -> None:
        """Recursively check every leaf for undefined variable references."""
        if isinstance(value, BaseModel):
            self._visit_model_variable_refs(value, path, defined)
            return

        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else str(key)
                self._visit_variable_refs(child, child_path, defined)
            return

        if isinstance(value, list):
            for index, child in enumerate(value):
                child_path = f"{path}[{index}]"
                self._visit_variable_refs(child, child_path, defined)
            return

        if self._is_unresolved_var(value):
            variable_name = extract_variable_name(value)
            if variable_name and variable_name not in defined:
                self._err(
                    f"Undefined variable '{variable_name}' referenced at "
                    f"'{path}'"
                )

    def _verify_variables(self) -> None:
        """Sweep the whole scenario tree for undefined variable references."""
        defined = set(self._s.variables.keys())
        self._visit_variable_refs(self._s, "", defined)
