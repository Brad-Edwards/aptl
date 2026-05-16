"""Property-based fuzz tests for ``aptl.utils.redaction.redact``.

Guards against regressions in the serialization-boundary redaction
helper:

- ``redact`` is a pure function: it must never raise on any input and
  must not mutate its argument.
- Long inline-credential-shaped strings must be processed within a
  deadline — the multi-pattern regex set
  (``_SENSITIVE_KV_RE`` / ``_AUTHORIZATION_RE`` / ``_CLI_FLAG_RE`` /
  ``_COOKIE_HEADER_RE`` / ``_URL_USERINFO_RE`` / ``_PEM_BLOCK_RE``)
  is the obvious place ReDoS could be introduced if a future change
  swapped a bounded character class for a nested quantifier.
- Dict keys whose lowercase form contains a sensitive token (and are
  not in the safe-allowlist) must have their values replaced with
  ``REDACTED``. The pre-/post-images for that property come from
  ``aptl.utils.redaction`` directly so the test follows the helper if
  the token set changes.

Run with ``pytest -m fuzz tests/test_redaction_fuzz.py``.
"""

import copy

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from aptl.utils import redaction
from aptl.utils.redaction import REDACTED, redact

pytestmark = pytest.mark.fuzz


# Recursive Hypothesis strategy: nested mix of dicts / lists / strings /
# ints / bools / None / floats. Depth-bound and size-bound so each
# example is cheap to evaluate.
_LEAF = (
    st.text(min_size=0, max_size=80)
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.booleans()
    | st.none()
)
_DICT_KEYS = st.text(min_size=1, max_size=30)
_NESTED = st.recursive(
    _LEAF,
    lambda children: (
        st.lists(children, max_size=5)
        | st.dictionaries(_DICT_KEYS, children, max_size=5)
        | st.tuples(children, children)
    ),
    max_leaves=20,
)


@given(value=_NESTED)
@settings(
    max_examples=300,
    deadline=1000,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_redact_never_raises_on_arbitrary_value(value):
    """``redact`` must accept any nested value without raising."""
    original = copy.deepcopy(value)
    result = redact(value)
    # Purity contract: input not mutated.
    assert value == original
    # Output is JSON-serializable shape: dicts/lists/scalars only.
    _assert_redacted_shape(result)


def _assert_redacted_shape(value):
    """Recursive shape check — JSON-compatible primitives only."""
    if isinstance(value, dict):
        for k, v in value.items():
            assert isinstance(k, str) or k is None or isinstance(k, (int, float, bool))
            _assert_redacted_shape(v)
    elif isinstance(value, list):
        for v in value:
            _assert_redacted_shape(v)
    else:
        # Tuples normalize to lists in ``redact`` output; the residual
        # set is the leaf types the helper passes through unchanged.
        assert isinstance(value, (str, int, float, bool)) or value is None


# Sensitive-key fuzz: keys whose lowercase form is guaranteed to match
# the sensitive-token rule and is not in the safe-allowlist. We build
# them by interleaving a sensitive token with surrounding letters so
# Hypothesis explores compound keys (``my_password_field``,
# ``access_token``, ``customer_secret_v2``) rather than just the literal
# token.
_SAFE_KEY_NAMES = redaction._SAFE_KEY_NAMES
_SENSITIVE_TOKENS = redaction._SENSITIVE_TOKENS


@st.composite
def _sensitive_dict_key(draw):
    """Compose a dict key whose lowercase contains a sensitive token.

    Returns a key that:
    - Lowercased contains at least one sensitive token from the helper.
    - Is NOT in the documented safe-allowlist (e.g. ``key_path``).
    """
    token = draw(st.sampled_from(_SENSITIVE_TOKENS))
    prefix = draw(
        st.text(
            alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"),
                                   whitelist_characters="_"),
            min_size=0,
            max_size=20,
        )
    )
    suffix = draw(
        st.text(
            alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"),
                                   whitelist_characters="_"),
            min_size=0,
            max_size=20,
        )
    )
    key = f"{prefix}{token}{suffix}"
    if key.lower() in _SAFE_KEY_NAMES:
        # Hypothesis shrinks toward simple names; force off the
        # allowlist by suffixing.
        key = f"{key}_x"
    return key


@given(
    sensitive_key=_sensitive_dict_key(),
    value=st.text(min_size=1, max_size=200),
)
@settings(max_examples=200, deadline=500)
def test_redact_masks_sensitive_dict_values(sensitive_key, value):
    """Values under a sensitive key are replaced with ``REDACTED``."""
    result = redact({sensitive_key: value})
    assert result == {sensitive_key: REDACTED}


# Strategy targeted at the credential-shaped branches of the redaction
# regex set. Plain ``st.text`` produces noise that rarely matches the
# credential prefixes, so future ReDoS regressions in
# ``_SENSITIVE_KV_RE`` / ``_AUTHORIZATION_RE`` / ``_BARE_BEARER_RE`` /
# ``_CLI_FLAG_RE`` / ``_COOKIE_HEADER_RE`` / ``_URL_USERINFO_RE`` /
# ``_PEM_BLOCK_RE`` could slip past. Each template is paired with a
# long random tail so a catastrophic backtracker on the tail-side of
# any of these patterns trips the deadline.
# Tail alphabet excludes characters that terminate any of the
# value-side patterns in ``aptl.utils.redaction``: ``\r``/``\n`` and
# whitespace (terminator for several regex value classes), ``'``/``"``
# (quote terminator), ``@`` (URL userinfo terminator), and the
# punctuation that ``_SENSITIVE_KV_RE`` rejects (``& , ; |``). Within
# that restriction the alphabet is intentionally diverse so a future
# catastrophic-backtracker on the value side has plenty of varied
# tail to chew on.
_TAIL_ALPHABET = st.characters(
    whitelist_categories=("Ll", "Lu", "Nd"),
    whitelist_characters="-_=./*+%",
)
_LONG_TAIL = st.text(alphabet=_TAIL_ALPHABET, min_size=200, max_size=2000)
_HOST_LIKE = st.text(
    alphabet=st.characters(whitelist_categories=("Ll",), whitelist_characters="."),
    min_size=3,
    max_size=40,
)
_USER_LIKE = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Nd"), whitelist_characters="_-"),
    min_size=1,
    max_size=20,
)


@st.composite
def _credential_shaped_string(draw):
    """Compose a string that hits one of the redaction regex families."""
    template = draw(st.sampled_from((
        "Authorization: Bearer {tail}",
        "Authorization: Basic {tail}",
        "Cookie: session={tail}",
        "Set-Cookie: connect.sid={tail}",
        "password={tail}",
        "api_key:{tail}",
        "access_token={tail}",
        "--password {tail}",
        "--client-secret {tail}",
        "Bearer {tail}",
        "https://{user}:{tail}@{host}/path",
        "-----BEGIN PRIVATE KEY-----\n{tail}\n-----END PRIVATE KEY-----",
    )))
    tail = draw(_LONG_TAIL)
    return template.format(
        tail=tail,
        user=draw(_USER_LIKE),
        host=draw(_HOST_LIKE),
    )


@given(payload=_credential_shaped_string())
@settings(
    max_examples=200,
    deadline=1000,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_redact_credential_shaped_strings_bounded(payload):
    """Credential-shaped strings with long tails redact in bounded time.

    The strategy guarantees one of the credential regex branches fires
    each example, so a future ReDoS regression in the inline-secret
    patterns trips the deadline. The redacted output must still be a
    string (the helper's only public contract for string input).
    """
    result = redact(payload)
    assert isinstance(result, str)
    assert REDACTED in result


@given(
    secret=st.text(
        # Restrict to a "distinctive" alphabet — digits and a few
        # uppercase letters that do NOT appear in the surrounding
        # template ``Authorization: Bearer ``. That removes the false
        # positives where the assertion ``secret not in result`` would
        # otherwise trip on a single ``r``/``e``/``a`` etc. that the
        # static template provides.
        alphabet="0123456789XYZQ",
        min_size=8,
        max_size=80,
    ),
)
@settings(max_examples=100, deadline=500)
def test_redact_authorization_header_masks_secret(secret):
    """``Authorization: Bearer <secret>`` strings mask the secret."""
    payload = f"Authorization: Bearer {secret}"
    result = redact(payload)
    assert secret not in result
    assert REDACTED in result
