"""Schema-first runtime contract tests."""

from __future__ import annotations

import json
from pathlib import Path

from aptl.core.runtime.contracts import schema_bundle


def test_published_contract_schemas_exist_and_match_bundle():
    repo_root = Path(__file__).resolve().parents[1]
    schemas_dir = repo_root / "schemas"
    published = {
        path.stem: json.loads(path.read_text(encoding="utf-8"))
        for path in schemas_dir.glob("*.json")
    }

    generated = schema_bundle()

    assert set(generated) <= set(published)
    for name, schema in generated.items():
        assert published[name] == schema


def test_closed_world_contract_models_for_runtime_envelopes():
    generated = schema_bundle()

    assert generated["workflow-result-envelope-v1"]["additionalProperties"] is False
    assert generated["operation-receipt-v1"]["additionalProperties"] is False
    assert generated["operation-status-v1"]["additionalProperties"] is False
    assert generated["runtime-snapshot-v1"]["additionalProperties"] is False
