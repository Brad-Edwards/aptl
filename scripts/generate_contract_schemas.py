#!/usr/bin/env python3
"""Generate checked-in JSON Schema bundles for APTL external contracts."""

from __future__ import annotations

import json
from pathlib import Path

from aptl.core.runtime.contracts import schema_bundle


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    schemas_dir = repo_root / "schemas"
    schemas_dir.mkdir(parents=True, exist_ok=True)
    bundle = schema_bundle()
    for name, schema in bundle.items():
        output_path = schemas_dir / f"{name}.json"
        output_path.write_text(
            json.dumps(schema, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
