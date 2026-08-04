"""Which scenario APTL realizes, and where its bytes come from, is configuration.

APTL currently hardcodes a scenario path inside its own tree. A backend is handed
a scenario; it does not own one. Selecting it is an operator decision made before
`aptl lab start`, not something the backend decides or switches at runtime.

The strict-config rules apply: unknown keys are errors, and a root that escapes
the project is refused rather than silently accepted.
"""

from __future__ import annotations

import json

import pytest

from aptl.core.config import AptlConfig, load_config


def _write(tmp_path, payload):
    path = tmp_path / "aptl.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_default_selects_the_techvault_env_pack():
    """The default is the TechVault env-pack, resolved by identity + digest (#875)."""

    config = AptlConfig()

    assert config.scenario.identity == "techvault"
    assert config.scenario.source == "env-pack"
    assert config.scenario.root is None


def test_an_operator_can_select_a_scenario_and_its_root(tmp_path):
    config = load_config(
        _write(
            tmp_path,
            {"scenario": {"identity": "bounded-participant-agency-techvault",
                          "root": "environments/bounded-participant"}},
        )
    )

    assert config.scenario.identity == "bounded-participant-agency-techvault"
    assert config.scenario.root == "environments/bounded-participant"


def test_unknown_scenario_keys_are_rejected(tmp_path):
    """ADR-025: aptl.json is strict at every level, so typos fail loudly."""

    config_path = _write(tmp_path, {"scenario": {"identiy": "typo"}})
    with pytest.raises(ValueError):
        load_config(config_path)


def test_an_empty_identity_is_rejected(tmp_path):
    config_path = _write(tmp_path, {"scenario": {"identity": "  "}})
    with pytest.raises(ValueError):
        load_config(config_path)


@pytest.mark.parametrize(
    "hostile", ["../elsewhere", "/etc", "packs/../../etc", "a\x00b"]
)
def test_a_root_that_escapes_the_project_is_refused(tmp_path, hostile):
    """A configured root is operator input and is treated as untrusted."""

    config_path = _write(tmp_path, {"scenario": {"root": hostile}})
    with pytest.raises(ValueError):
        load_config(config_path)


def test_the_configured_scenario_is_what_the_start_path_resolves(tmp_path):
    """Configuration that nothing reads is not configuration.

    The bundle seam was once wired this way — a type with tests and no caller —
    so the wiring itself is asserted here rather than the model in isolation.
    """

    from aptl.backends.raes import _resolve_scenario_path

    config = AptlConfig.model_validate(
        {"scenario": {"identity": "bounded-participant-agency-techvault"}}
    )

    resolved = _resolve_scenario_path(tmp_path, None, config)

    assert resolved.name == "bounded-participant-agency-techvault.sdl.yaml"


def test_an_explicit_scenario_path_still_wins(tmp_path):
    """Selecting one explicitly must override the configured default."""

    from pathlib import Path

    from aptl.backends.raes import _resolve_scenario_path

    config = AptlConfig()
    explicit = Path("scenarios") / "paper-agent-loop.sdl.yaml"

    assert _resolve_scenario_path(tmp_path, explicit, config).name == (
        "paper-agent-loop.sdl.yaml"
    )


def test_a_configured_root_anchors_the_scenario(tmp_path):
    """The scenario's bytes come from the configured root, not the checkout."""

    from aptl.backends.raes import _resolve_scenario_path

    config = AptlConfig.model_validate(
        {"scenario": {"identity": "demo", "root": "environments/demo"}}
    )

    resolved = _resolve_scenario_path(tmp_path, None, config)

    assert (tmp_path / "environments" / "demo") in resolved.parents
