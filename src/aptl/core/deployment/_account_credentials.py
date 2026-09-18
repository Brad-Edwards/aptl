"""Realize the credential class TechVault-style scenarios declare per account.

RAES accounts declare ``password_strength`` (``weak``/``medium``/``strong``).
That is an in-world fact: a weak account is the credential-guessing surface an
attacker is meant to find, and a strong one is meant to resist that. Realizing
every account with ``samba-tool user create --random-password`` produces a
range where no declared weak credential exists, which is a different
environment than the one the scenario declares (issue #1006).

Realization is default-open, so the backend chooses *how*: this module mints a
password whose class matches the declaration, and the caller proves the
credential by authenticating with it before the account counts as realized.

Secret handling
---------------

* A weak or medium password is a scenario fixture: it exists to be guessed or
  cracked inside the range. It is still written only to the operator's
  range-private disclosure directory, mode 0600 under a 0700 parent, with the
  same helpers the other generated-credential producers use.
* Strong passwords stay target-generated (``--random-password``): nothing needs
  to know them, so nothing reads them back.
* No password is logged. Callers pass them straight to the provider argv inside
  the target boundary and never into a shell string.
"""

from __future__ import annotations

import os
import secrets
import tempfile
from pathlib import Path

from aptl.core.credentials import (
    _canonical_generated_path,
    _ensure_secure_dir,
)

ACCOUNT_CREDENTIALS_ROOT_RELPATH = Path(".aptl/realization/account-credentials")

WEAK = "weak"
MEDIUM = "medium"
STRONG = "strong"

# The credential classes this backend knows how to make true. A declared class
# outside this set is refused at interpret time rather than realized as
# something else.
REALIZABLE_PASSWORD_STRENGTHS = frozenset({WEAK, MEDIUM, STRONG})

# RAES's own default for an account that declares no strength. Mirroring it
# keeps an omitted field meaning what RAES says it means, rather than becoming
# an APTL-invented class.
DEFAULT_PASSWORD_STRENGTH = MEDIUM

# Classes whose concrete secret the backend chooses and therefore discloses.
# `strong` is absent on purpose: it stays generated inside the target.
BACKEND_MINTED_STRENGTHS = frozenset({WEAK, MEDIUM})

# A weak password is meant to fall to a wordlist plus a small mutation — that is
# the declared attack surface. These are the shapes that show up in real
# credential-guessing corpora, not random strings shortened to look weak.
_WEAK_WORDS = (
    "Password",
    "Welcome",
    "Summer",
    "Winter",
    "Spring",
    "Autumn",
    "Company",
    "Letmein",
)
_WEAK_SUFFIXES = ("1", "12", "123", "2024", "2025", "!")

# A medium password resists a plain wordlist but not a targeted rule-based
# crack: a word, a separator, a short number, and one symbol.
_MEDIUM_WORDS = ("Harbor", "Lantern", "Quarry", "Meadow", "Falcon", "Cobalt")


def password_for_strength(strength: str) -> str:
    """Mint a password whose class matches the declared strength.

    Raises ``ValueError`` for a class this backend does not mint, so a caller
    cannot silently substitute a different credential class.
    """

    if strength == WEAK:
        word = secrets.choice(_WEAK_WORDS)
        return f"{word}{secrets.choice(_WEAK_SUFFIXES)}"
    if strength == MEDIUM:
        word = secrets.choice(_MEDIUM_WORDS)
        return f"{word}-{secrets.randbelow(900) + 100}!"
    raise ValueError(f"backend does not mint a {strength!r} password")


def disclose_account_credential(
    scenario_root: Path, *, node: str, username: str, password: str, strength: str
) -> Path:
    """Write one realized credential to the operator's range-private directory.

    Returns the path written. The operator needs these: a declared weak account
    is only usable as a fixture if someone can say what it is.
    """

    root = _canonical_generated_path(scenario_root, ACCOUNT_CREDENTIALS_ROOT_RELPATH)
    _ensure_secure_dir(root)
    node_dir = _canonical_generated_path(
        scenario_root, ACCOUNT_CREDENTIALS_ROOT_RELPATH / _safe_segment(node)
    )
    _ensure_secure_dir(node_dir)
    target = _canonical_generated_path(
        scenario_root,
        ACCOUNT_CREDENTIALS_ROOT_RELPATH
        / _safe_segment(node)
        / _safe_segment(username),
    )
    _write_operator_only(target, f"{strength}\n{password}\n")
    return target


def _write_operator_only(target: Path, content: str) -> None:
    """Atomically write a 0600 file inside an already contained parent.

    ``credentials._atomic_write_secure`` deliberately widens its output to 0644
    so a container can read it across a bind mount. Nothing mounts these files —
    they exist for the operator — so they keep the mode ``mkstemp`` gives them
    rather than being widened for a reader that does not exist.
    """

    parent = target.parent
    fd, tmp_name = tempfile.mkstemp(
        dir=parent, prefix=f".{target.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _safe_segment(value: str) -> str:
    """Reduce an identity token to a single safe path segment."""

    cleaned = "".join(ch for ch in value if ch.isalnum() or ch in "._-")
    if not cleaned or cleaned.startswith(".") or cleaned in {".", ".."}:
        raise ValueError("unsafe path segment")
    return cleaned
