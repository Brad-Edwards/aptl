#!/usr/bin/env python3
"""Bind a local image cut to its source and exact output bytes."""

import argparse
import hashlib
import json
from pathlib import Path
import re


def digest(path: Path) -> str:
    with path.open('rb') as handle:
        return 'sha256:' + hashlib.file_digest(handle, 'sha256').hexdigest()


def artifacts(directory: Path) -> dict[str, str]:
    return {name: digest(directory / name) for name in (
        'seat-disk.qcow2', 'seat-image-config.json',
    )}


def verify_manifest(directory: Path, manifest_path: Path, manifest_digest: str) -> None:
    """Bind a registry candidate to the exact local disk and config before signing."""

    payload = manifest_path.read_bytes()
    try:
        manifest = json.loads(payload)
        if 'sha256:' + hashlib.sha256(payload).hexdigest() != manifest_digest:
            raise ValueError('manifest digest mismatch')
        if manifest['schemaVersion'] != 2 or manifest['mediaType'] != 'application/vnd.oci.image.manifest.v1+json':
            raise ValueError('unsupported manifest')
        layers = manifest['layers']
        if not isinstance(layers, list) or len(layers) != 1:
            raise ValueError('unexpected layers')
        for descriptor, name, media_type in (
            (layers[0], 'seat-disk.qcow2', 'application/vnd.aptl.seat.disk.v1+qcow2'),
            (manifest['config'], 'seat-image-config.json', 'application/vnd.aptl.seat.config.v1+json'),
        ):
            path = directory / name
            if (descriptor['digest'] != digest(path)
                or type(descriptor['size']) is not int
                or descriptor['size'] != path.stat().st_size
                or descriptor['mediaType'] != media_type):
                raise ValueError('artifact descriptor mismatch')
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        raise SystemExit('registry candidate does not match the local image cut') from exc


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('write', 'verify', 'verify-manifest'))
    parser.add_argument('directory', type=Path)
    parser.add_argument('--commit')
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--manifest-digest')
    parser.add_argument('--dirty', choices=('0', '1'), default='1')
    args = parser.parse_args()
    if args.action == 'verify-manifest':
        if args.manifest is None or args.manifest_digest is None:
            parser.error('manifest and manifest digest are required')
        verify_manifest(args.directory, args.manifest, args.manifest_digest)
        return
    path = args.directory / 'seat-build.json'
    if args.action == 'write':
        if not args.commit or not re.fullmatch(r'[0-9a-f]{40}', args.commit):
            raise SystemExit('invalid source commit')
        record = {
            'schema_version': 'aptl.seat-build/v1', 'source_commit': args.commit,
            'dirty_source': args.dirty == '1', 'artifacts': artifacts(args.directory),
        }
        path.write_text(json.dumps(record, sort_keys=True) + '\n')
        return
    try:
        record = json.loads(path.read_bytes())
        valid = (
            record['schema_version'] == 'aptl.seat-build/v1'
            and record['dirty_source'] is False
            and re.fullmatch(r'[0-9a-f]{40}', record['source_commit'])
            and record['artifacts'] == artifacts(args.directory)
        )
    except (OSError, ValueError, KeyError, TypeError):
        valid = False
    if not valid:
        raise SystemExit('seat publication requires an unchanged image cut from clean source')
    print(record['source_commit'])


if __name__ == '__main__':
    main()
