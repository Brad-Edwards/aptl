"""Stateful-override dumper; Wazuh is realized generically (issue #875).

APTL used to hand-author complete Compose service definitions for the Wazuh
manager/indexer here — image, entrypoint, env, healthcheck, ulimits, and ~15
read-only binds pulled from APTL's own ``config/`` tree, none of it authored in
the SDL. That was the exemplar of the SDL-authority defect class: the backend
owning range content and run shape the scenario should declare.

The Wazuh cluster is now realized by the same generic path as every other app:
its image/networks/env/entrypoint come from the generated base compose
(:mod:`_compose_node_generation`), its config files from declared ``content``
placements, its certificates and rendered config from declared generated-artifact
consumers, and its data volumes from declared persistent volumes. Nothing is
injected here that the pack did not author, so this module keeps only the YAML
dumper the stateful override is written with.
"""

from __future__ import annotations

import yaml


class OverrideMapping(dict):
    """A complete Compose service definition that replaces the base service.

    Retained for the ``!override`` representer below; the generic stateful mounts
    merge with the base service, so no producer emits one today.
    """


class StatefulDumper(yaml.SafeDumper):
    """Safe YAML dumper with Compose's explicit replacement tag."""


StatefulDumper.add_representer(
    OverrideMapping,
    lambda dumper, value: dumper.represent_mapping("!override", value),
)


def wazuh_service_definitions() -> dict[str, dict[str, object]]:
    """Return no graph-owned service definitions.

    Wazuh is realized generically from its declared desired-state; the backend no
    longer hand-authors its service definitions (issue #875). Kept as a seam so
    the stateful-override assembly does not need to special-case its absence.
    """

    return {}
