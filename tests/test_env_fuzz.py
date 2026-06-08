"""Property-based fuzz tests for ``.env`` parsing and validation.

Guards against regressions in ``aptl.core.env``:

- ``load_dotenv`` must accept any byte sequence written to disk and
  either return a ``dict[str, str]`` or raise ``FileNotFoundError``.
  Unhandled ``UnicodeDecodeError``, ``ValueError``, or ``OSError``
  leaking into the lab-start path is a real bug.
- ``env_vars_from_dict`` must accept any ``dict[str, str]`` and either
  return an ``EnvVars`` or raise ``ValueError``.
- ``find_placeholder_env_values`` is a pure detector — it must never
  raise.

Run with ``pytest -m fuzz tests/test_env_fuzz.py``; excluded from the
default suite by ``pyproject.toml`` (``addopts = "-m 'not fuzz'"``).
"""

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from aptl.core.env import (
    EnvVars,
    _NO_PLACEHOLDER_VARS,
    env_vars_from_dict,
    find_placeholder_env_values,
    load_dotenv,
)
from aptl.utils.placeholders import PLACEHOLDER_MARKERS

pytestmark = pytest.mark.fuzz


# Arbitrary byte sequence — the real contract for ``load_dotenv`` is
# "any bytes on disk → dict or one of the documented public
# exceptions". ``Path.read_text()`` decodes UTF-8 strictly, so invalid
# byte sequences raise ``UnicodeDecodeError``, which is a subclass of
# ``ValueError`` and therefore inside the documented exception set
# already. Using ``st.binary()`` + ``write_bytes()`` ensures the test
# actually exercises that branch instead of confining itself to
# UTF-8-decodable text (which would silently overstate coverage —
# issue #213 codex review cycle 2).
_ENV_BYTES = st.binary(min_size=0, max_size=2000)

_ENV_VAR_NAMES = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters="_",
    ),
    min_size=1,
    max_size=40,
)
_ENV_VAR_VALUES = st.text(min_size=0, max_size=200)

_REQUIRED_VARS = ("INDEXER_USERNAME", "INDEXER_PASSWORD", "API_USERNAME", "API_PASSWORD")


@given(body=_ENV_BYTES)
@settings(
    max_examples=300,
    deadline=1000,
    suppress_health_check=[
        HealthCheck.too_slow,
        HealthCheck.function_scoped_fixture,
    ],
)
def test_load_dotenv_arbitrary_bytes_bounded_outcomes(tmp_path, body):
    """Any byte sequence on disk yields a dict or a documented exception.

    Lines are skipped if they are blank, comment-only, or contain no
    ``=``. Everything else partitions on the first ``=`` and yields a
    string-keyed string-valued entry. Invalid UTF-8 raises
    ``UnicodeDecodeError`` (subclass of ``ValueError``), which the
    documented contract already admits.
    """
    env_file = tmp_path / ".env"
    env_file.write_bytes(body)

    try:
        result = load_dotenv(env_file)
    except (FileNotFoundError, ValueError):
        return

    assert isinstance(result, dict)
    for key, value in result.items():
        assert isinstance(key, str)
        assert isinstance(value, str)


# Non-empty values for required-var success-path generation. Empty
# strings count as missing per ``env_vars_from_dict``, so excluding them
# from the strategy is what makes the strategy actually exercise the
# successful construction path — issue #213 codex review (test_env_fuzz
# split, finding 2).
_NONEMPTY_VALUE = st.text(min_size=1, max_size=200)
_OPTIONAL_VALUE = st.text(min_size=0, max_size=200)


@st.composite
def _valid_env_dict(draw):
    """Build a dict where every required var is present and non-empty.

    Optional fields (``DASHBOARD_USERNAME``, ``DASHBOARD_PASSWORD``,
    ``WAZUH_CLUSTER_KEY``) are randomly included so the successful
    construction path also exercises optional-default fallbacks.
    """
    env: dict[str, str] = {var: draw(_NONEMPTY_VALUE) for var in _REQUIRED_VARS}
    for optional in ("DASHBOARD_USERNAME", "DASHBOARD_PASSWORD", "WAZUH_CLUSTER_KEY"):
        if draw(st.booleans()):
            env[optional] = draw(_OPTIONAL_VALUE)
    return env


@given(env=_valid_env_dict())
@settings(max_examples=200, deadline=500)
def test_env_vars_from_dict_valid_input_constructs_envvars(env):
    """When every required var is present and non-empty, the call succeeds.

    Property: ``env_vars_from_dict(env)`` returns an ``EnvVars`` whose
    required fields round-trip from the input dict, and whose optional
    fields take either the supplied value or the documented default.
    """
    result = env_vars_from_dict(env)

    assert isinstance(result, EnvVars)
    assert result.indexer_username == env["INDEXER_USERNAME"]
    assert result.indexer_password == env["INDEXER_PASSWORD"]
    assert result.api_username == env["API_USERNAME"]
    assert result.api_password == env["API_PASSWORD"]
    assert result.dashboard_username == env.get("DASHBOARD_USERNAME", "kibanaserver")
    assert result.dashboard_password == env.get("DASHBOARD_PASSWORD", "")
    assert result.wazuh_cluster_key == env.get("WAZUH_CLUSTER_KEY", "")


@given(
    env=_valid_env_dict(),
    drop_var=st.sampled_from(_REQUIRED_VARS),
    empty=st.booleans(),
)
@settings(max_examples=100, deadline=500)
def test_env_vars_from_dict_missing_required_raises(env, drop_var, empty):
    """A missing or empty required var raises ``ValueError`` and names it."""
    if empty:
        env[drop_var] = ""
    else:
        env.pop(drop_var, None)

    with pytest.raises(ValueError, match=drop_var):
        env_vars_from_dict(env)


@given(
    env=st.dictionaries(
        keys=_ENV_VAR_NAMES,
        values=_ENV_VAR_VALUES,
        max_size=20,
    ),
)
@settings(max_examples=300, deadline=500)
def test_find_placeholder_env_values_never_raises(env):
    """``find_placeholder_env_values`` returns a ``list[str]`` and never raises."""
    result = find_placeholder_env_values(env)
    assert isinstance(result, list)
    for var in result:
        assert isinstance(var, str)


_PLACEHOLDER_MARKER_VALUES = st.sampled_from(PLACEHOLDER_MARKERS)


@given(
    sensitive_var=st.sampled_from(_NO_PLACEHOLDER_VARS),
    marker=_PLACEHOLDER_MARKER_VALUES,
)
@settings(max_examples=100, deadline=500)
def test_find_placeholder_env_values_flags_known_markers(sensitive_var, marker):
    """Every sensitive var carrying a known placeholder marker is flagged.

    The sensitive-var inventory is sampled from
    ``aptl.core.env._NO_PLACEHOLDER_VARS`` directly so a new entry
    there (e.g. ``WAZUH_CLUSTER_KEY``, which is rendered into
    ``wazuh_manager.conf`` per ADR-028) is automatically covered
    without an edit here. Property derived from
    ``aptl.utils.placeholders.PLACEHOLDER_MARKERS``: if a sensitive var
    contains any marker substring (case-insensitive), it must appear in
    the result list. Catches regressions where a layer bypasses
    ``contains_placeholder``.
    """
    env = {sensitive_var: marker}
    assert sensitive_var in find_placeholder_env_values(env)
