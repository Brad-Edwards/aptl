"""Cross-language parity gate for the redaction layer (issue #386).

The shared corpus at ``tests/fixtures/redaction_parity_corpus.json`` is consumed
by BOTH this pytest module and
``mcp/aptl-mcp-common/tests/redaction.parity.test.ts``. Each case pins an input
to its expected redacted output; the Python and TypeScript redactors must each
reproduce it exactly. If the two ~950-LOC hand-maintained implementations'
secret patterns drift apart, one side's parity test fails — closing the silent
divergence hazard (ARCH-386-01 redact-05 / dup-01) that two independent
redactors otherwise carry, which ADR-035 explicitly forbids (no second
redaction taxonomy).

To extend coverage, add a case to the corpus generator and regenerate the
fixture; both languages pick it up automatically.
"""

import json
from pathlib import Path

import pytest

from aptl.utils.redaction import redact

_CORPUS_PATH = Path(__file__).parent / "fixtures" / "redaction_parity_corpus.json"
_CORPUS = json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))


def test_corpus_is_non_empty():
    # Guard against a truncated/empty fixture silently passing the gate.
    assert len(_CORPUS) >= 40


@pytest.mark.parametrize("case", _CORPUS, ids=[c["name"] for c in _CORPUS])
def test_redaction_parity_corpus(case):
    assert redact(case["input"]) == case["expected"]
