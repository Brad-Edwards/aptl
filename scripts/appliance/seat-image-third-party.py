#!/usr/bin/env python3
"""Print the third-party container images a seat image must preload.

The lab's compose definition is the only statement of what TechVault runs, so
the list is derived from it rather than maintained by hand and left to drift.
Images this project builds are excluded: the bake exports those from the exact
local build instead of pulling them.
"""

from __future__ import annotations

import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker-compose.yml"

# Images this repository builds. They are exported from the local build, so
# pulling them would fetch a different artefact than the one baked in.
_PROJECT_PREFIXES = ("aptl/", "aptl-")

# A seat preloads what the lab starts. A bare tag is accepted because the
# compose file is the pin of record for these services; a reference that names
# no tag at all is refused rather than silently resolving to :latest here.
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*(?::[A-Za-z0-9._-]+)?$")


def third_party_images(document: dict) -> list[str]:
    """Return the sorted, de-duplicated third-party image references."""

    references: set[str] = set()
    for name, service in (document.get("services") or {}).items():
        reference = service.get("image")
        if not reference:
            continue
        if not isinstance(reference, str) or not _REFERENCE.fullmatch(reference):
            raise SystemExit(f"service {name} declares an unusable image reference")
        if reference.startswith(_PROJECT_PREFIXES):
            continue
        if "${" in reference:
            raise SystemExit(f"service {name} image is not pinned in the compose file")
        references.add(reference)
    if not references:
        raise SystemExit("compose file declares no third-party images to preload")
    return sorted(references)


def main() -> int:
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    for reference in third_party_images(document):
        print(reference)
    return 0


if __name__ == "__main__":
    sys.exit(main())
