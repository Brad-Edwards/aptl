"""Property-based fuzz tests for credential rendering.

Guards against regressions in the credentialized config render path
(`aptl.core.credentials`):

- ReDoS / backtracking regressions: enforces Hypothesis deadlines so a
  future replacement of the linear block-scoped scan with a
  backtracking regex fails as a test rather than hangs the lab start.
- Unhandled-exception regressions: every fuzzed input must produce
  either a rendered `Path` or one of the documented public exception
  types (`CredentialRenderError`, `PathContainmentError`,
  `FileNotFoundError`). Unhandled `TypeError`, `KeyError`,
  `AttributeError`, etc. mean the render boundary leaked an internal
  failure to a caller.
- #183 regression: an SSL-key file path inside
  ``<indexer><ssl><key>...</key></ssl></indexer>`` must NOT be replaced
  even when adjacent ``<cluster><key>...</key></cluster>`` is. The
  property here is "outside-cluster `<key>` is byte-equal to input".

Run with ``pytest -m fuzz tests/test_credentials_fuzz.py``; excluded
from the default suite by ``pyproject.toml`` (``addopts = "-m 'not
fuzz'"``).

See ``docs/testing/property-based-parser-tests.md`` for the boundary
ownership and guardrails this module follows.
"""

from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from aptl.core.credentials import (
    CredentialRenderError,
    PathContainmentError,
    sync_dashboard_config,
    sync_manager_config,
)


def _yaml_double_quoted_escape(value: str) -> str:
    """Mirror ``_dashboard_transform`` in ``aptl.core.credentials``.

    The production transform applies exactly this two-step escape before
    interpolation: ``\\`` first, then ``"``. Keeping it as a single
    helper here means the rendered-content assertion below holds the
    transform's escape contract without a second public surface.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')

pytestmark = pytest.mark.fuzz


_DASHBOARD_SOURCE_RELPATH = Path("config/wazuh_dashboard/wazuh.yml")
_MANAGER_SOURCE_RELPATH = Path("config/wazuh_cluster/wazuh_manager.conf")
_DASHBOARD_RENDERED_RELPATH = Path(".aptl/config/wazuh_dashboard/wazuh.yml")
_MANAGER_RENDERED_RELPATH = Path(".aptl/config/wazuh_cluster/wazuh_manager.conf")


def _layout_dashboard_template(project_dir: Path, content: str) -> None:
    target = project_dir / _DASHBOARD_SOURCE_RELPATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


def _layout_manager_template(project_dir: Path, content: str) -> None:
    target = project_dir / _MANAGER_SOURCE_RELPATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


_VALID_DASHBOARD_TEMPLATE = (
    "hosts:\n"
    "  - default:\n"
    '      url: "https://wazuh.manager"\n'
    "      port: 55000\n"
    '      username: "wazuh-wui"\n'
    '      password: "placeholder"\n'
    "      run_as: false\n"
)

_VALID_MANAGER_TEMPLATE_WITH_SSL = (
    "<ossec_config>\n"
    "  <indexer>\n"
    "    <ssl>\n"
    "      <key>{ssl_key_path}</key>\n"
    "    </ssl>\n"
    "  </indexer>\n"
    "  <cluster>\n"
    "    <name>wazuh</name>\n"
    "    <key>{cluster_key_placeholder}</key>\n"
    "  </cluster>\n"
    "</ossec_config>\n"
)


# Hypothesis strategies. Exclude C0/C1 control codepoints (``\n``,
# ``\r``, NUL, etc.) and surrogates from credential strategies: text-mode
# I/O in ``_atomic_write_secure`` normalizes line endings (``\r`` →
# ``\n``), and credentials carrying raw CR/LF cannot round-trip through
# a ``.env`` file anyway, so they are outside the realistic input space
# for ``sync_dashboard_config`` / ``sync_manager_config``. Everything
# else — punctuation, quotes, backslashes, regex specials,
# non-Latin scripts, emoji — is in scope and the production code's
# YAML/XML escapes are expected to handle them.
_PRINTABLE_CHARS = st.characters(
    blacklist_categories=("Cc", "Cs"),
)
_PASSWORD_LIKE = st.text(alphabet=_PRINTABLE_CHARS, min_size=0, max_size=200)
_CLUSTER_KEY_LIKE = st.text(alphabet=_PRINTABLE_CHARS, min_size=0, max_size=200)
# SSL key paths in the template must not contain ``<`` (would terminate
# the `<key>` element). Restrict the alphabet so the test injects a
# well-formed XML element rather than fuzzing XML well-formedness — the
# property under test is "non-cluster <key> is preserved", not "the XML
# parser handles broken markup".
_FILESYSTEM_PATH = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters="/._-",
    ),
    min_size=1,
    max_size=120,
)


@given(api_password=_PASSWORD_LIKE)
@settings(
    max_examples=200,
    deadline=2000,
    suppress_health_check=[
        HealthCheck.too_slow,
        HealthCheck.function_scoped_fixture,
    ],
)
def test_sync_dashboard_config_bounded_outcomes(tmp_path, api_password):
    """Every fuzzed password against a valid template must render cleanly.

    Property: for every Hypothesis-generated ``api_password``, the call
    against a canonical valid dashboard template completes within the
    deadline and returns the rendered output ``Path``; the file at that
    path carries the password in its documented YAML-escaped form.
    There is no bounded-exception branch here — the template is valid,
    so any ``CredentialRenderError`` / ``PathContainmentError`` /
    ``FileNotFoundError`` indicates the render boundary regressed on a
    class of credentials it should be able to accept (e.g. an escape
    bug that rejects a special character).
    """
    _layout_dashboard_template(tmp_path, _VALID_DASHBOARD_TEMPLATE)

    out = sync_dashboard_config(tmp_path, api_password)

    expected_path = (tmp_path / _DASHBOARD_RENDERED_RELPATH).resolve()
    assert isinstance(out, Path)
    assert out == expected_path
    rendered = out.read_text()
    # Positive structural check: the rendered file carries the password
    # in its documented YAML-escaped form. This already proves the
    # substitution happened — a separate ``"placeholder" not in
    # rendered`` check would false-positive when Hypothesis generates a
    # password that itself contains the literal placeholder substring
    # (e.g. ``placeholder``, ``xplaceholderx``).
    assert f'password: "{_yaml_double_quoted_escape(api_password)}"' in rendered


@given(cluster_key=_CLUSTER_KEY_LIKE)
@settings(
    max_examples=200,
    deadline=2000,
    suppress_health_check=[
        HealthCheck.too_slow,
        HealthCheck.function_scoped_fixture,
    ],
)
def test_sync_manager_config_bounded_outcomes(tmp_path, cluster_key):
    """Every fuzzed cluster_key against a valid template must render cleanly.

    Same shape as the dashboard valid-template test: the template is
    canonical, so any documented exception here is a regression. The
    bounded-exception pattern is reserved for
    ``test_sync_manager_config_arbitrary_template_no_redos``, which
    deliberately feeds in arbitrary / broken templates.
    """
    placeholder = "placeholder_cluster_key"
    _layout_manager_template(
        tmp_path,
        "<ossec_config>\n"
        "  <cluster>\n"
        f"    <key>{placeholder}</key>\n"
        "  </cluster>\n"
        "</ossec_config>\n",
    )

    out = sync_manager_config(tmp_path, cluster_key)

    expected_path = (tmp_path / _MANAGER_RENDERED_RELPATH).resolve()
    assert isinstance(out, Path)
    assert out == expected_path
    rendered = out.read_text()
    # Positive structural check (see dashboard test for rationale): a
    # standalone ``placeholder not in rendered`` would false-positive
    # when Hypothesis generates a cluster_key whose XML-escaped value
    # contains the placeholder substring.
    assert f"<key>{xml_escape(cluster_key)}</key>" in rendered


# Templates that may or may not contain ``<cluster>...<key>...</key>...
# </cluster>``. Use a small alphabet biased toward XML-like punctuation
# so Hypothesis can build pathological shapes (unbalanced tags, repeated
# ``<cluster>`` openers, ``<key>`` nested oddly) without spending the
# entire budget on irrelevant unicode noise. The block-scoping logic in
# ``_manager_transform`` must handle every shape without crashing.
_TEMPLATE_FUZZ_ALPHABET = "<>/abcdefkluster\n "


@given(template=st.text(alphabet=_TEMPLATE_FUZZ_ALPHABET, min_size=0, max_size=800))
@settings(
    max_examples=200,
    deadline=1500,
    suppress_health_check=[
        HealthCheck.too_slow,
        HealthCheck.function_scoped_fixture,
    ],
)
def test_sync_manager_config_arbitrary_template_no_redos(tmp_path, template):
    """Arbitrary XML-ish templates must not hang or raise unknown types.

    The property under test is strictly "the renderer either completes
    within the deadline or raises one of the documented public
    exceptions"; success-path artifact correctness for canonical
    templates is owned by
    ``test_sync_manager_config_bounded_outcomes``. The fuzz alphabet
    here is biased toward XML-like punctuation so most examples
    deliberately fail to contain a complete ``<cluster><key>...</key>
    </cluster>`` block and land in the ``CredentialRenderError``
    branch; that is the intent — the regression this test catches is
    a hang or an unhandled exception class on broken markup, not a
    return-value correctness regression.

    A future change that replaced the O(n) block-scoping logic in
    ``_manager_transform`` with a backtracking regex like
    ``<cluster>(.*?)</cluster>`` would blow this deadline on inputs
    with many opened-but-unclosed ``<cluster>`` markers and long
    interior runs.
    """
    _layout_manager_template(tmp_path, template)

    try:
        sync_manager_config(tmp_path, "fuzz-cluster-key")
    except (CredentialRenderError, PathContainmentError, FileNotFoundError):
        pass


@given(
    ssl_key_path=_FILESYSTEM_PATH,
    cluster_key=st.text(alphabet=_PRINTABLE_CHARS, min_size=0, max_size=80),
)
@settings(
    max_examples=200,
    deadline=2000,
    suppress_health_check=[
        HealthCheck.too_slow,
        HealthCheck.function_scoped_fixture,
    ],
)
def test_sync_manager_config_preserves_ssl_key_paths(
    tmp_path, ssl_key_path, cluster_key,
):
    """#183 regression in property form: outside-cluster ``<key>`` is preserved.

    The block-scoped scan in ``_manager_transform`` must replace
    ``<key>`` only inside ``<cluster>`` blocks. Any ``<key>`` outside a
    cluster (Wazuh writes SSL key file paths into
    ``<indexer><ssl><key>``) must be byte-equal to the original after
    rendering.
    """
    placeholder = "old_cluster_key"
    _layout_manager_template(
        tmp_path,
        _VALID_MANAGER_TEMPLATE_WITH_SSL.format(
            ssl_key_path=ssl_key_path,
            cluster_key_placeholder=placeholder,
        ),
    )

    sync_manager_config(tmp_path, cluster_key)

    rendered = (tmp_path / _MANAGER_RENDERED_RELPATH).read_text()
    # Two positive structural checks. Together they prove the #183
    # invariant: the SSL element keeps its byte-equal value AND the
    # cluster element carries the new XML-escaped value. A separate
    # ``placeholder not in rendered`` check would false-positive when
    # the generated ssl_key_path or cluster_key contains the
    # placeholder substring.
    assert f"<key>{ssl_key_path}</key>" in rendered, (
        "Outside-cluster <key> must be preserved byte-equal (#183)"
    )
    assert f"<key>{xml_escape(cluster_key)}</key>" in rendered, (
        "Inside-cluster <key> must be replaced with the XML-escaped value"
    )
