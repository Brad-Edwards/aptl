"""Deterministic lab-fixture bindings for a scenario's required flag variables.

env-packs 6.0.0 declares the TechVault CTF flag *values* as required SDL
variables (``flag_ad_user``, ``flag_ad_root``) with no default — "in-world
facts" the consuming backend must supply before the scenario instantiates
(``Variable '...' is required and has no provided value or default``).

APTL supplies a deterministic, reproducible lab-fixture value for each such
variable so a clean admission never fails and two admissions of the same
scenario stay byte-identical (the reproducibility record and canonical digests
depend on that determinism). These are lab-fixture flags — deliberately placed,
non-secret research content — not operator secrets; the unpredictable,
verifiable flag *token* is a separate concern owned by the per-node
``techvault:flag-signing-profile/v2`` HMAC mechanism (see
``aptl.core.deployment._flag_signing_keys``). Only variables that follow the
flag naming convention are auto-bound; any other required variable without a
value remains a genuine admission error rather than being silently masked.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from raes.scenario import Scenario

# The env-pack flag-value convention. A required, defaultless string variable
# whose name begins with this prefix is a scenario-declared lab flag value.
_FLAG_VARIABLE_PREFIX = "flag_"


def _flag_value(variable_name: str) -> str:
    """Return the deterministic lab-fixture flag value for ``variable_name``."""

    digest = hashlib.sha256(f"aptl:techvault:{variable_name}".encode()).hexdigest()
    return f"APTL{{{variable_name}-{digest[:24]}}}"


def flag_variable_bindings(scenario: "Scenario") -> dict[str, str]:
    """Return deterministic values for the scenario's required flag variables.

    Covers every declared variable that is required, has no default, is a string,
    and follows the ``flag_`` naming convention. Non-flag required variables are
    intentionally left unbound so a real missing binding still fails admission.
    """

    variables = getattr(scenario, "variables", None)
    if not variables:
        return {}
    bindings: dict[str, str] = {}
    for name, variable in variables.items():
        if not name.startswith(_FLAG_VARIABLE_PREFIX):
            continue
        if not getattr(variable, "required", False):
            continue
        if getattr(variable, "default", None) is not None:
            continue
        value_type = getattr(variable, "type", None)
        type_name = getattr(value_type, "value", value_type)
        if type_name not in (None, "string"):
            continue
        bindings[name] = _flag_value(name)
    return bindings
