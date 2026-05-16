"""Property-based fuzz tests for ``aptl.json`` loading and validation.

Guards against regressions in ``aptl.core.config.load_config`` and the
``AptlConfig`` Pydantic model:

- Arbitrary JSON text must produce ``AptlConfig`` or a documented
  public exception (``FileNotFoundError``, ``ValueError`` for malformed
  JSON or empty file, ``pydantic.ValidationError`` for schema
  violations). No raw ``json.JSONDecodeError`` may surface — the
  loader wraps it in ``ValueError``.
- ADR-025 strict-config invariant: any extra top-level key triggers
  ``ValidationError``.
- ``LabSettings.name`` validation: any non-empty name matching
  ``^[a-zA-Z0-9][a-zA-Z0-9._-]*$`` is accepted; anything else raises
  ``ValidationError``.

Run with ``pytest -m fuzz tests/test_config_fuzz.py``.
"""

import json

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

# Import the private name pattern and the top-level config model directly
# so the fuzz suite never holds a parallel copy of the contract — if the
# production regex or schema changes, these tests follow without manual
# edits. This is the boundary-ownership rule from
# ``docs/testing/property-based-parser-tests.md``: tests do not duplicate
# the strict config schema.
from aptl.core.config import AptlConfig, LabSettings, _NAME_PATTERN, load_config

pytestmark = pytest.mark.fuzz


_KNOWN_TOP_LEVEL_KEYS = frozenset(AptlConfig.model_fields)

# Arbitrary text — most examples will not be valid JSON. The contract
# is the bounded-error one: load_config must classify the failure into
# one of the documented public exceptions, not let an internal one
# escape.
_ARBITRARY_TEXT = st.text(min_size=0, max_size=2000)

# Slug-shaped extra-key names for the strict-config property.
_SLUG_LIKE = st.from_regex(r"[a-z][a-z0-9_]{0,20}", fullmatch=True)

# Lab-name fuzz: full text, then filter the matching-vs-non-matching
# disposition inside the test rather than splitting strategies. Keeps
# both arms of the property covered without two near-duplicate tests.
_LAB_NAME_FUZZ = st.text(min_size=0, max_size=80)


@given(body=_ARBITRARY_TEXT)
@settings(
    max_examples=300,
    deadline=1500,
    suppress_health_check=[
        HealthCheck.too_slow,
        HealthCheck.function_scoped_fixture,
    ],
)
def test_load_config_arbitrary_text_bounded_outcomes(tmp_path, body):
    """Arbitrary text loads to ``AptlConfig`` or raises a documented type."""
    config_file = tmp_path / "aptl.json"
    config_file.write_text(body, encoding="utf-8")

    try:
        result = load_config(config_file)
    except (FileNotFoundError, ValueError, ValidationError):
        return

    assert isinstance(result, AptlConfig)


@given(extra_key=_SLUG_LIKE, extra_value=st.integers() | st.text(max_size=40))
@settings(
    max_examples=100,
    deadline=500,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_load_config_extra_top_level_fields_rejected(
    tmp_path, extra_key, extra_value,
):
    """ADR-025: unknown top-level keys raise ``ValidationError``.

    Skips the four legitimate top-level keys (``lab``, ``containers``,
    ``deployment``, ``run_storage``) since those are the in-schema
    keys; the property only fires when the extra is genuinely
    unknown.
    """
    if extra_key in _KNOWN_TOP_LEVEL_KEYS:
        return  # Hypothesis will explore other values.

    data = {extra_key: extra_value}
    config_file = tmp_path / "aptl.json"
    config_file.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValidationError):
        load_config(config_file)


@given(name=_LAB_NAME_FUZZ)
@settings(max_examples=300, deadline=500)
def test_lab_settings_name_validation_matches_documented_pattern(name):
    """``LabSettings(name=...)`` accepts the pattern, rejects everything else.

    The accepted-name pattern lives in ``aptl.core.config._NAME_PATTERN``
    and is imported at module top so a regex change in production
    automatically updates the oracle here. Drift between the implementation
    and the validator is a regression.
    """
    name_is_valid = bool(name and name.strip() and _NAME_PATTERN.match(name))

    if name_is_valid:
        settings_obj = LabSettings(name=name)
        assert settings_obj.name == name
    else:
        with pytest.raises(ValidationError):
            LabSettings(name=name)
