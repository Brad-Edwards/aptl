#!/usr/bin/env python3
"""Measure staged payload and unique stored/expanded container-layer bytes."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import tarfile
import tempfile
from pathlib import Path

import rfc8785


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="aptl-image-measure-") as temporary:
        image_path = Path(temporary) / "oci-images.tar"
        with tarfile.open(args.payload, "r:") as payload:
            member = payload.getmember("oci-images.tar")
            source = payload.extractfile(member)
            if source is None or not member.isfile() or member.size > 500 * 1024**3:
                raise ValueError("offline image archive is invalid")
            with image_path.open("xb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
        with tarfile.open(image_path, "r:") as images:
            manifest_source = images.extractfile("manifest.json")
            if manifest_source is None:
                raise ValueError("image manifest is unavailable")
            manifest = json.load(manifest_source)
            layers = {name for image in manifest for name in image.get("Layers", [])}
            stored = 0
            expanded = 0
            for name in sorted(layers):
                member = images.getmember(name)
                source = images.extractfile(member)
                if source is None or not member.isfile() or member.size > 100 * 1024**3:
                    raise ValueError("image layer is invalid")
                stored += member.size
                with tarfile.open(fileobj=source, mode="r|*") as layer:
                    for item in layer:
                        if item.size < 0:
                            raise ValueError("image layer member is invalid")
                        expanded += item.size
                        if expanded > 500 * 1024**3:
                            raise ValueError("expanded image closure exceeds limit")
    document = {
        "staged_profile_assets_bytes": args.payload.stat().st_size,
        "unique_image_compressed_bytes": stored,
        "unique_image_expanded_bytes": expanded,
    }
    descriptor = os.open(
        args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
    )
    with os.fdopen(descriptor, "wb") as output:
        output.write(rfc8785.dumps(document))


if __name__ == "__main__":
    main()
