#!/usr/bin/env bash
set -euo pipefail

: "${APTL_RELEASE_TAG:?release tag is required}"
: "${APTL_BASE_IMAGE_URL:?base image URL is required}"
: "${APTL_BASE_IMAGE_SHA256:?base image SHA-256 is required}"
: "${APTL_BASE_IMAGE_SIZE_BYTES:?base image size is required}"
: "${APTL_IMAGE_NAMESPACE:?GHCR image namespace is required}"
: "${APTL_GUEST_PYTHON_VERSION:?guest Python target is required}"

source_root=$PWD
test "$(git describe --tags --exact-match HEAD)" = "$APTL_RELEASE_TAG"
test "$(git rev-parse HEAD)" = "$(git rev-list -n 1 "$APTL_RELEASE_TAG")"

root=$PWD/build/appliance
test ! -e "$root"
install -d -m 0700 "$root" "$root/input" "$root/cache" "$root/candidate"
cleanup() {
  rm -f "$root/input/candidate-private.pem"
  docker logout ghcr.io >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

python -m venv "$root/venv"
"$root/venv/bin/pip" install --require-hashes -r requirements/ci.txt
"$root/venv/bin/python" -m build --no-isolation --outdir "$root/dist"
"$root/venv/bin/pip" install --require-hashes -r requirements/runtime.txt
"$root/venv/bin/pip" install --no-deps "$root"/dist/aptl_labs-*.whl
install -d -m 0700 "$root/wheelhouse"
target_python=$(command -v "python${APTL_GUEST_PYTHON_VERSION}")
"$target_python" -m pip download --require-hashes -r requirements/runtime.txt \
  --dest "$root/wheelhouse"
cp "$root"/dist/aptl_labs-*.whl "$root/wheelhouse/"

pull_tag() {
  local package=$1
  local canonical=$2
  docker pull "${APTL_IMAGE_NAMESPACE,,}/${package}:${APTL_RELEASE_TAG}"
  docker tag "${APTL_IMAGE_NAMESPACE,,}/${package}:${APTL_RELEASE_TAG}" "$canonical"
}

pull_tag generic-samba-ad-wazuh-agent-base aptl/generic-samba-ad-wazuh-agent-base:latest
pull_tag generic-samba-ad-base aptl/generic-samba-ad-base:latest
pull_tag generic-systemd-wazuh-agent-base aptl/generic-systemd-wazuh-agent-base:latest
pull_tag generic-systemd-wazuh-agent-base-debian aptl/generic-systemd-wazuh-agent-base-debian:latest
pull_tag generic-systemd-base-debian aptl/generic-systemd-base-debian:latest
pull_tag generic-systemd-node22-base aptl/generic-systemd-node22-base:latest
pull_tag generic-wazuh-agent-base-debian aptl/generic-wazuh-agent-base-debian:latest
pull_tag generic-systemd-base aptl/generic-systemd-base:latest
pull_tag suricata-wazuh-agent aptl/suricata-wazuh-agent:latest
pull_tag kali-capture aptl-kali-capture:latest
pull_tag network-boundary-helper aptl-network-boundary-helper:4
pull_tag appliance-egress-proxy aptl-appliance-egress-proxy:1
pull_tag operator-access-proxy aptl/operator-access-proxy:latest

cd "$root"
"$root/venv/bin/aptl" appliance acquire-images \
  --image-archive input/oci-images.tar --image-roles input/image-roles.json
"$root/venv/bin/aptl" appliance assemble-inputs \
  --staging-dir offline-staging --wheelhouse wheelhouse \
  --image-archive input/oci-images.tar --image-roles input/image-roles.json \
  --target-python-version "$APTL_GUEST_PYTHON_VERSION" \
  --target-architecture x86_64
"$root/venv/bin/aptl" appliance bundle \
  --staging-dir offline-staging --output input/offline-payload.tar
"$root/venv/bin/aptl" appliance stage-download \
  --url "$APTL_BASE_IMAGE_URL" --cache-dir cache \
  --filename ubuntu-base.qcow2 --sha256 "$APTL_BASE_IMAGE_SHA256" \
  --size-bytes "$APTL_BASE_IMAGE_SIZE_BYTES"
cp "cache/${APTL_BASE_IMAGE_SHA256#sha256:}/ubuntu-base.qcow2" input/base.qcow2
cp "$source_root/appliance/guest/provision-offline.sh" input/provision-offline.sh
cp "$source_root/appliance/guest/scan-golden.sh" input/scan-golden.sh
chmod 0500 input/provision-offline.sh input/scan-golden.sh
"$root/venv/bin/aptl" appliance plan-build --build-root "$root" \
  --base-image input/base.qcow2 --offline-payload input/offline-payload.tar \
  --provisioner input/provision-offline.sh --scanner input/scan-golden.sh \
  --output-image candidate/aptl-golden.qcow2 \
  --inventory-output candidate/golden-inventory.json \
  --request input/golden-build.json
"$root/venv/bin/aptl" appliance build \
  --build-root "$root" --request "$root/input/golden-build.json"

cp input/offline-payload.tar candidate/offline-payload.tar
cp offline-staging/inputs.json candidate/inputs.json
cp input/golden-build.json candidate/golden-build.json
cp input/provision-offline.sh candidate/provision-offline.sh
cp input/scan-golden.sh candidate/scan-golden.sh
"$root/venv/bin/aptl" appliance write-boundary-policy \
  --output candidate/boundary-policy.json
"$root/venv/bin/python" - "$root" "$source_root" <<'PYTHON'
import hashlib
import json
import pathlib
import tarfile
import sys

root = pathlib.Path(sys.argv[1])
source_root = pathlib.Path(sys.argv[2])
candidate = root / "candidate"
members = {
    "participant-profile": "participant-profiles/techvault-full-v1/profile.json",
    "participant-readiness": "participant-profiles/techvault-full-v1/readiness.json",
    "participant-asset-lock": "participant-profiles/techvault-full-v1/asset-lock.json",
}
with tarfile.open(root / "offline-staging/project.tar", "r:") as archive:
    for name, member in members.items():
        source = archive.extractfile(member)
        if source is None:
            raise SystemExit(f"missing {member}")
        (candidate / f"{name}.json").write_bytes(source.read())

def digest(path):
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

version = __import__("os").environ["APTL_RELEASE_TAG"].removeprefix("v")
commit = __import__("subprocess").check_output(
    ["git", "rev-parse", "HEAD"], text=True, cwd=source_root
).strip()
namespace = __import__("os").environ["APTL_IMAGE_NAMESPACE"].lower()
tag = __import__("os").environ["APTL_RELEASE_TAG"]

def repo_digest(package):
    value = __import__("subprocess").check_output(
        ["docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", f"{namespace}/{package}:{tag}"],
        text=True,
    ).strip()
    if "@sha256:" not in value:
        raise SystemExit(f"missing repository digest for {package}")
    return value

artifacts = [
    ("canonical-inputs", "canonical-inputs", "inputs.json"),
    ("golden-build-request", "golden-build-request", "golden-build.json"),
    ("golden-provisioner", "golden-provisioner", "provision-offline.sh"),
    ("golden-scanner", "golden-scanner", "scan-golden.sh"),
    ("golden-disk", "golden-disk", "aptl-golden.qcow2"),
    ("offline-payload", "offline-payload", "offline-payload.tar"),
    ("participant-profile", "participant-profile", "participant-profile.json"),
    ("participant-readiness", "participant-readiness", "participant-readiness.json"),
    ("participant-asset-lock", "participant-asset-lock", "participant-asset-lock.json"),
    ("boundary-policy", "boundary-policy", "boundary-policy.json"),
    ("golden-inventory", "golden-inventory", "golden-inventory.json"),
]
template = {
    "schema_version": "aptl.appliance-candidate-template/v1",
    "candidate_id": f"aptl-{version}-candidate-x86_64",
    "source": {"aptl_version": version, "source_tag": tag, "source_commit": commit},
    "guest": {
        "os_id": "ubuntu", "os_version": "26.04", "architecture": "x86_64",
        "disk_format": "qcow2", "base_image_digest": __import__("os").environ["APTL_BASE_IMAGE_SHA256"],
        "immutable": True, "overlay_strategy": "qcow2-backing-file",
    },
    "artifacts": [
        {"artifact_id": artifact_id, "kind": kind, "path": path}
        for artifact_id, kind, path in artifacts
    ],
    "participant": {"profile_id": "techvault-full", "profile_version": 1},
    "boundary": {
        "boundary_helper_image": repo_digest("network-boundary-helper"),
        "egress_proxy_image": repo_digest("appliance-egress-proxy"),
    },
    "host_prerequisites": {
        "architecture": "x86_64", "vcpus": 8, "memory_bytes": 34359738368,
        "disk_bytes": 268435456000, "hardware_virtualization": True,
        "local_adapter": "qemu-kvm", "supported_hypervisors": ["qemu-kvm"],
    },
    "delivery": {
        "participant_ui_digest": digest(candidate / "participant-profile.json"),
        "participant_routes_digest": digest(candidate / "participant-readiness.json"),
        "canonical_inputs_digest": digest(candidate / "inputs.json"),
        "host_mcp_contract": "aptl.restricted-ssh-mcp/v1",
        "adapters": [
            {"adapter_id": "local-kvm", "kind": "local-kvm", "payload_unchanged": True},
            {"adapter_id": "hosted", "kind": "hosted", "payload_unchanged": True},
        ],
    },
    "build_request_digest": digest(root / "input/golden-build.json"),
}
(root / "input/candidate-template.json").write_text(json.dumps(template, separators=(",", ":")))
PYTHON

openssl genpkey -algorithm ED25519 -out input/candidate-private.pem
openssl pkey -in input/candidate-private.pem -pubout -out candidate/candidate-public.pem
"$root/venv/bin/aptl" appliance prepare-candidate \
  --candidate-dir candidate --template input/candidate-template.json
"$root/venv/bin/aptl" appliance seal-candidate \
  --candidate-dir candidate --private-key input/candidate-private.pem

manifest_digest=$("$root/venv/bin/python" -c \
  'import json; print(json.load(open("candidate/candidate-manifest.sig.json"))["manifest_digest"])')
install -d -m 0700 candidate-publication
"$root/venv/bin/aptl" appliance split-distribution \
  --source candidate/aptl-golden.qcow2 \
  --output-dir candidate-publication/golden \
  --release-id "aptl-${APTL_RELEASE_TAG#v}-candidate-x86_64" \
  --manifest-digest "$manifest_digest" --private-key input/candidate-private.pem
"$root/venv/bin/aptl" appliance split-distribution \
  --source candidate/offline-payload.tar \
  --output-dir candidate-publication/offline \
  --release-id "aptl-${APTL_RELEASE_TAG#v}-candidate-x86_64" \
  --manifest-digest "$manifest_digest" --private-key input/candidate-private.pem
tar --create --file candidate-publication/candidate-metadata.tar \
  --exclude=aptl-golden.qcow2 --exclude=offline-payload.tar \
  --directory candidate .
cleanup
trap - EXIT INT TERM
