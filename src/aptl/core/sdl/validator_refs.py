"""Named-reference index and generic reference validation.

Relationships and objectives reference scenario elements by name, optionally
qualified (``nodes.web``) or bare (``web``). ``_RefIndexMixin`` builds the
alias map those passes resolve against and validates a single reference for
existence and ambiguity.
"""

from collections import defaultdict

from aptl.core.sdl.validator_base import _ValidatorCore


class _RefIndexMixin(_ValidatorCore):
    """Builds and queries the named-element alias index."""

    def _qualified_service_refs(self) -> set[str]:
        """Return fully qualified ``nodes.<n>.services.<s>`` refs."""
        refs: set[str] = set()
        for node_name, node in self._s.nodes.items():
            for service in node.services:
                if service.name:
                    refs.add(f"nodes.{node_name}.services.{service.name}")
        return refs

    def _qualified_acl_refs(self) -> set[str]:
        """Return fully qualified ``infrastructure.<n>.acls.<a>`` refs."""
        refs: set[str] = set()
        for infra_name, infra in self._s.infrastructure.items():
            for acl in infra.acls:
                if acl.name:
                    refs.add(f"infrastructure.{infra_name}.acls.{acl.name}")
        return refs

    def _workflow_step_refs(self) -> set[str]:
        """Return ``<workflow>.<step>`` references for every workflow step."""
        refs: set[str] = set()
        for workflow_name, workflow in self._s.workflows.items():
            for step_name in workflow.steps:
                refs.add(f"{workflow_name}.{step_name}")
        return refs

    def _ref_index_top_level(
        self, index: dict[str, set[str]]
    ) -> None:
        """Populate ``index`` with the top-level section aliases."""
        top_level_sections: tuple[tuple[str, dict[str, object], bool], ...] = (
            ("nodes", self._s.nodes, True),
            ("features", self._s.features, True),
            ("conditions", self._s.conditions, True),
            ("vulnerabilities", self._s.vulnerabilities, True),
            ("infrastructure", self._s.infrastructure, False),
            ("metrics", self._s.metrics, True),
            ("evaluations", self._s.evaluations, True),
            ("tlos", self._s.tlos, True),
            ("goals", self._s.goals, True),
            ("content", self._s.content, True),
            ("accounts", self._s.accounts, True),
            ("agents", self._s.agents, True),
            ("objectives", self._s.objectives, True),
            ("workflows", self._s.workflows, True),
            ("relationships", self._s.relationships, True),
            ("variables", self._s.variables, True),
            ("injects", self._s.injects, True),
            ("events", self._s.events, True),
            ("scripts", self._s.scripts, True),
            ("stories", self._s.stories, True),
        )

        for section_name, section, allow_bare in top_level_sections:
            for name in section:
                canonical = f"{section_name}.{name}"
                index[canonical].add(canonical)
                if allow_bare:
                    index[name].add(canonical)

    def _ref_index_nested(self, index: dict[str, set[str]]) -> None:
        """Populate ``index`` with entity, content-item and service/ACL refs."""
        for entity_name in self._all_entity_names():
            canonical = f"entities.{entity_name}"
            index[canonical].add(canonical)
            index[entity_name].add(canonical)

        for content_name, content in self._s.content.items():
            for item in content.items:
                if not item.name:
                    continue
                canonical = f"content.{content_name}.items.{item.name}"
                index[canonical].add(canonical)
                index[item.name].add(canonical)

        for ref in self._qualified_service_refs():
            index[ref].add(ref)
        for ref in self._qualified_acl_refs():
            index[ref].add(ref)

    def _named_ref_index(self, *, targetable: bool = False) -> dict[str, set[str]]:
        """Build the alias map for generic relationship/objective refs.

        Bare refs stay available for most top-level sections when they are
        unambiguous. Qualified refs are always accepted for top-level sections,
        and are required for infrastructure entries because those keys
        intentionally mirror node names.
        """
        index: dict[str, set[str]] = defaultdict(set)
        self._ref_index_top_level(index)
        self._ref_index_nested(index)

        if not targetable:
            return {alias: set(candidates) for alias, candidates in index.items()}

        disallowed_prefixes = (
            "variables.",
            "objectives.",
            "workflows.",
        )
        filtered: dict[str, set[str]] = {}
        for alias, candidates in index.items():
            keep = {
                candidate
                for candidate in candidates
                if not candidate.startswith(disallowed_prefixes)
            }
            if keep:
                filtered[alias] = keep
        return filtered

    def _validate_named_ref(
        self,
        ref: str,
        *,
        owner_label: str,
        ref_label: str,
        targetable: bool = False,
    ) -> None:
        """Validate a generic reference against the named-element index."""
        index = self._named_ref_index(targetable=targetable)
        candidates = index.get(ref)
        if not candidates:
            qualifier = "targetable " if targetable else ""
            self._err(
                f"{owner_label} {ref_label} '{ref}' does not reference any "
                f"defined {qualifier}element"
            )
            return

        if len(candidates) > 1:
            choices = ", ".join(sorted(candidates))
            self._err(
                f"{owner_label} {ref_label} '{ref}' is ambiguous; use one of: "
                f"{choices}"
            )

    def _all_named_elements(self) -> set[str]:
        """Collect all named element keys across all scenario sections."""
        return set(self._named_ref_index().keys())

    def _all_targetable_elements(self) -> set[str]:
        """Collect named elements that can serve as objective targets."""
        return set(self._named_ref_index(targetable=True).keys())
