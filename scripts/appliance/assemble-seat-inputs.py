#!/usr/bin/env python3
"""Acquire the realized TechVault closure and bind the saved participant profile."""

from __future__ import annotations

import argparse
import json
import subprocess
import tarfile
from pathlib import Path

import yaml

from aptl.appliance.input_images import (
    canonical_image_references,
    compose_runtime_image_aliases,
    runtime_image_tag,
)
from aptl.appliance.input_profile import _write_full_profile
from aptl.core.config import AptlConfig
from aptl.core.scenario_bundle import env_pack_bundle
from aptl.validation.curated_live_proof import expected_bundle_matrix


def _docker(*args: str) -> str:
    return subprocess.check_output(
        ["docker", *args], text=True, stdin=subprocess.DEVNULL
    ).strip()


def _local_image_ids(path: Path) -> dict[str, str]:
    """Read the IDs produced by this bake's unique-tagged local build."""
    rows = [line.split() for line in path.read_text().splitlines()]
    if not rows or any(
        len(row) != 3 or not row[2].startswith("sha256:") for row in rows
    ):
        raise ValueError("local image build lock is invalid")
    result = {canonical: image_id for canonical, _unique, image_id in rows}
    if len(result) != len(rows):
        raise ValueError("local image build lock has duplicate names")
    return result


def _add_compose_images(project: Path, save_tags: dict[str, str]) -> None:
    """Include Compose services outside the scenario's service matrix."""
    compose = yaml.safe_load((project / "docker-compose.yml").read_text())
    for service in compose["services"].values():
        tag = service.get("image")
        if not isinstance(tag, str) or tag in save_tags:
            continue
        if not tag.startswith(("aptl/", "aptl-")):
            _docker("pull", "--quiet", tag)
        save_tags[tag] = _docker("image", "inspect", "--format", "{{.Id}}", tag)


def assemble(
    project: Path, work: Path, local_image_lock: Path
) -> tuple[dict[str, str], dict[str, str]]:
    """Resolve every role to the image Docker will save, then write the profile."""
    bundle = env_pack_bundle(work / "packs")
    matrix = expected_bundle_matrix(project, AptlConfig(), bundle)
    references = canonical_image_references(project, bundle)
    expected_roles = {"scenario." + name for name in matrix.expected_services}
    if not expected_roles <= references.keys():
        raise ValueError("TechVault realization has an unbound service image")

    identities: dict[str, str] = {}
    save_tags: dict[str, str] = {}
    local_ids = _local_image_ids(local_image_lock)
    for reference in sorted(set(references.values())):
        runtime_tag = runtime_image_tag(reference)
        if "@sha256:" in reference:
            _docker("pull", "--quiet", reference)
            _docker("tag", reference, runtime_tag)
        elif not reference.startswith(("aptl/", "aptl-")):
            raise ValueError(f"unlocked third-party image: {reference}")
        identity = _docker("image", "inspect", "--format", "{{.Id}}", runtime_tag)
        if not identity.startswith("sha256:"):
            raise ValueError(f"invalid Docker image identity: {reference}")
        if reference in local_ids and identity != local_ids[reference]:
            raise ValueError(f"local image tag changed during bake: {reference}")
        identities[reference] = identity
        save_tags[runtime_tag] = identity

    # Compose may refer to a pinned repository by a versioned tag while the
    # realization names its digest. Give the guest that authored tag as an
    # alias of the exact image inspected above.
    for alias, reference in compose_runtime_image_aliases(project, references).items():
        _docker("tag", runtime_image_tag(reference), alias)
        if (
            _docker("image", "inspect", "--format", "{{.Id}}", alias)
            != identities[reference]
        ):
            raise ValueError(f"Compose image alias differs from lock: {alias}")
        save_tags[alias] = identities[reference]

    # These tags are saved with the disk, so the guest can start offline.
    _add_compose_images(project, save_tags)

    for canonical, image_id in local_ids.items():
        if canonical not in save_tags:
            if (
                _docker("image", "inspect", "--format", "{{.Id}}", canonical)
                != image_id
            ):
                raise ValueError(f"local image tag changed during bake: {canonical}")
            save_tags[canonical] = image_id

    roles = {role: identities[reference] for role, reference in references.items()}
    return roles, dict(sorted(save_tags.items()))


def verify_archive(
    archive_path: Path, roles: dict[str, str], tag_ids: dict[str, str]
) -> dict[str, str]:
    """Map Docker's inspected manifest IDs to the guest's saved config IDs."""
    with tarfile.open(archive_path, "r:") as archive:
        manifest_file = archive.extractfile("manifest.json")
        if manifest_file is None:
            raise ValueError("saved image archive has no manifest")
        manifest = json.load(manifest_file)
        index_file = (
            archive.extractfile("index.json")
            if "index.json" in archive.getnames()
            else None
        )
        index = json.load(index_file) if index_file is not None else None
        index_map: dict[str, str] = {}
        if index is not None:
            for descriptor in index["manifests"]:
                digest = descriptor["digest"]
                current = digest
                for _depth in range(4):
                    blob = archive.extractfile(
                        "blobs/sha256/" + current.removeprefix("sha256:")
                    )
                    if blob is None:
                        raise ValueError(
                            "saved Docker index has a missing image manifest"
                        )
                    document = json.load(blob)
                    if "config" in document:
                        index_map[digest] = document["config"]["digest"]
                        break
                    candidates = [
                        item
                        for item in document.get("manifests", ())
                        if item.get("platform", {}).get("os") == "linux"
                        and item.get("platform", {}).get("architecture") == "amd64"
                    ]
                    if len(candidates) != 1:
                        raise ValueError(
                            "saved Docker image has no unique amd64 manifest"
                        )
                    current = candidates[0]["digest"]
                else:
                    raise ValueError("saved Docker index nesting exceeds limit")
    saved: dict[str, str] = {}
    for entry in manifest:
        config = entry["Config"]
        image_id = "sha256:" + Path(config).name.removesuffix(".json")
        for tag in entry.get("RepoTags") or ():
            if tag in saved and saved[tag] != image_id:
                raise ValueError(f"saved image tag is ambiguous: {tag}")
            saved[tag] = image_id
    if set(saved) != set(tag_ids):
        raise ValueError("saved Docker archive differs from the TechVault image lock")
    # Docker with a containerd image store reports OCI manifest digests as
    # image IDs. `docker load` materializes the native config digest instead.
    # The index binds those two identities; older Docker stores report config
    # IDs directly and omit the index.
    for tag, local_id in tag_ids.items():
        config_id = index_map.get(local_id, local_id)
        if saved[tag] != config_id:
            raise ValueError(f"saved Docker image differs from inspected tag: {tag}")
    converted = {
        role: index_map.get(local_id, local_id) for role, local_id in roles.items()
    }
    if not set(converted.values()) <= set(saved.values()):
        raise ValueError("saved Docker archive omits a TechVault image role")
    return converted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--local-image-lock", type=Path, required=True)
    parser.add_argument("--roles-output", type=Path, required=True)
    parser.add_argument("--tags-output", type=Path, required=True)
    parser.add_argument("--tag-ids-output", type=Path, required=True)
    parser.add_argument("--verify-archive", type=Path)
    args = parser.parse_args()
    if args.verify_archive is not None:
        saved_roles = verify_archive(
            args.verify_archive,
            json.loads(args.roles_output.read_text()),
            json.loads(args.tag_ids_output.read_text()),
        )
        bundle = env_pack_bundle(args.work / "profile-packs")
        matrix = expected_bundle_matrix(args.project, AptlConfig(), bundle)
        _write_full_profile(args.project, bundle, matrix, saved_roles)
        args.roles_output.write_text(
            json.dumps(saved_roles, indent=2, sort_keys=True) + "\n"
        )
        return 0
    roles, tags = assemble(args.project, args.work, args.local_image_lock)
    args.roles_output.write_text(json.dumps(roles, indent=2, sort_keys=True) + "\n")
    args.tags_output.write_text("\n".join(tags) + "\n")
    args.tag_ids_output.write_text(json.dumps(tags, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
