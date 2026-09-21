#!/usr/bin/env bash
set -euo pipefail

: "${APTL_RELEASE_TAG:?release tag is required}"
: "${APTL_QUALIFIED_INPUTS:?qualified input directory is required}"
: "${APTL_RELEASE_SIGNING_KEY_PEM:?release signing key is required}"
: "${APTL_RELEASE_PUBLIC_KEY_PEM:?configured release trust anchor is required}"
: "${APTL_QUALIFICATION_PUBLIC_KEY_PEM:?configured qualification trust anchor is required}"
: "${APTL_REDISTRIBUTION_REVIEW_JSON:?approved redistribution review is required}"

root=$PWD/build/appliance-seal
test ! -e "$root"
install -d -m 0700 "$root" "$root/candidate" "$root/release/artifacts" \
    "$root/release/evidence" "$root/publication"

candidate_metadata=$(find "$APTL_QUALIFIED_INPUTS" -type f \
    -name candidate-metadata.tar -print -quit)
machine_a=$(find "$APTL_QUALIFIED_INPUTS" -type f -name machine-a.json -print -quit)
machine_b=$(find "$APTL_QUALIFIED_INPUTS" -type f -name machine-b.json -print -quit)
test -n "$candidate_metadata" -a -n "$machine_a" -a -n "$machine_b"
candidate_publication=$(dirname "$candidate_metadata")

python3 - "$candidate_metadata" "$root/candidate" <<'PYTHON'
import pathlib
import sys
import tarfile

with tarfile.open(pathlib.Path(sys.argv[1]), "r:") as archive:
    archive.extractall(pathlib.Path(sys.argv[2]), filter="data")
PYTHON

python3 -m venv "$root/venv"
"$root/venv/bin/pip" install --require-hashes -r requirements/ci.txt
"$root/venv/bin/pip" install --no-deps .

reconstruct() {
    local directory=$1
    local output=$2
    local index signature
    index=$(find "$candidate_publication/$directory" -maxdepth 1 -type f \
        -name '*.distribution.json' -print -quit)
    signature=$(find "$candidate_publication/$directory" -maxdepth 1 -type f \
        -name '*.distribution.sig.json' -print -quit)
    test -n "$index" -a -n "$signature"
    "$root/venv/bin/aptl" appliance reconstruct-distribution \
        --index "$index" --signature "$signature" \
        --chunks-dir "$candidate_publication/$directory" \
        --public-key "$root/candidate/candidate-public.pem" \
        --output "$root/candidate/$output"
}
reconstruct golden aptl-golden.qcow2
reconstruct offline offline-payload.tar
"$root/venv/bin/aptl" appliance verify-candidate \
    --candidate-dir "$root/candidate" \
    --public-key "$root/candidate/candidate-public.pem"

"$root/venv/bin/aptl" appliance aggregate-machine-drills \
    --candidate-dir "$root/candidate" \
    --candidate-public-key "$root/candidate/candidate-public.pem" \
    --report "$machine_a" --report "$machine_b" \
    --output "$root/release/evidence/machine-drill.json"

qualification_dir=$(find "$APTL_QUALIFIED_INPUTS" -type d \
    -path '*/evidence/participant-qualification' -print -quit)
test -n "$qualification_dir"
for evidence in participant-qualification.json run-record.json snapshot.json; do
    test -f "$qualification_dir/$evidence" -a ! -L "$qualification_dir/$evidence"
done
test -f "$qualification_dir/qualification-public.pem" \
    -a ! -L "$qualification_dir/qualification-public.pem"

cp --reflink=auto "$root/candidate/aptl-golden.qcow2" \
    "$root/release/artifacts/aptl-golden.qcow2"
cp --reflink=auto "$root/candidate/offline-payload.tar" \
    "$root/release/artifacts/offline-payload.tar"
cp "$root/candidate/inputs.json" "$root/release/evidence/inputs.json"
cp "$root/candidate/participant-profile.json" \
    "$root/release/evidence/participant-profile.json"
cp "$root/candidate/participant-readiness.json" \
    "$root/release/evidence/participant-readiness.json"
cp "$root/candidate/participant-asset-lock.json" \
    "$root/release/evidence/participant-asset-lock.json"
cp "$root/candidate/boundary-policy.json" \
    "$root/release/evidence/boundary-policy.json"
cp "$root/candidate/golden-inventory.json" \
    "$root/release/evidence/golden-inventory.json"
cp "$qualification_dir/participant-qualification.json" \
    "$root/release/evidence/participant-qualification.json"
cp "$qualification_dir/run-record.json" "$root/release/evidence/run-record.json"
cp "$qualification_dir/snapshot.json" "$root/release/evidence/snapshot.json"
printf '%s' "$APTL_REDISTRIBUTION_REVIEW_JSON" \
    >"$root/release/evidence/redistribution-review.json"
cp "$qualification_dir/qualification-public.pem" "$root/qualification-public.pem"
printf '%s' "$APTL_QUALIFICATION_PUBLIC_KEY_PEM" \
    >"$root/configured-qualification-public.pem"
openssl pkey -pubin -in "$root/qualification-public.pem" -outform DER \
    >"$root/qualification-public.der"
openssl pkey -pubin -in "$root/configured-qualification-public.pem" -outform DER \
    >"$root/configured-qualification-public.der"
cmp "$root/qualification-public.der" "$root/configured-qualification-public.der"

"$root/venv/bin/python" - "$root/candidate/candidate-manifest.json" \
    "$root/release-template.json" <<'PYTHON'
import json
import pathlib
import sys

candidate = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
artifacts = (
    ("canonical-inputs", "canonical-inputs", "evidence/inputs.json"),
    ("golden-disk", "golden-disk", "artifacts/aptl-golden.qcow2"),
    ("offline-payload", "offline-payload", "artifacts/offline-payload.tar"),
    ("participant-profile", "participant-profile", "evidence/participant-profile.json"),
    ("participant-readiness", "participant-readiness", "evidence/participant-readiness.json"),
    ("participant-asset-lock", "participant-asset-lock", "evidence/participant-asset-lock.json"),
    ("participant-qualification", "participant-qualification", "evidence/participant-qualification.json"),
    ("participant-run-record", "participant-run-record", "evidence/run-record.json"),
    ("participant-snapshot", "participant-snapshot", "evidence/snapshot.json"),
    ("redistribution-review", "redistribution-review", "evidence/redistribution-review.json"),
    ("boundary-policy", "boundary-policy", "evidence/boundary-policy.json"),
    ("golden-inventory", "golden-inventory", "evidence/golden-inventory.json"),
    ("machine-drill", "machine-drill", "evidence/machine-drill.json"),
)
template = {
    "schema_version": "aptl.appliance-release-template/v1",
    "release_id": f"aptl-v{candidate['source']['aptl_version']}-x86_64",
    "source": candidate["source"],
    "guest": candidate["guest"],
    "artifacts": [
        {"artifact_id": artifact_id, "kind": kind, "path": path}
        for artifact_id, kind, path in artifacts
    ],
    "participant": candidate["participant"],
    "boundary": {
        "boundary_helper_image": candidate["boundary"]["boundary_helper_image"],
        "egress_proxy_image": candidate["boundary"]["egress_proxy_image"],
    },
    "host_prerequisites": candidate["host_prerequisites"],
    "delivery": candidate["delivery"],
    "upgrade_strategy": "replace-golden-create-overlay",
}
pathlib.Path(sys.argv[2]).write_text(json.dumps(template, separators=(",", ":")))
PYTHON

printf '%s' "$APTL_RELEASE_SIGNING_KEY_PEM" >"$root/release-private.pem"
chmod 0600 "$root/release-private.pem"
cleanup() {
    rm -f "$root/release-private.pem"
}
trap cleanup EXIT INT TERM
openssl pkey -in "$root/release-private.pem" -pubout -out "$root/release-public.pem"
printf '%s' "$APTL_RELEASE_PUBLIC_KEY_PEM" >"$root/configured-release-public.pem"
openssl pkey -pubin -in "$root/release-public.pem" -outform DER \
    >"$root/release-public.der"
openssl pkey -pubin -in "$root/configured-release-public.pem" -outform DER \
    >"$root/configured-release-public.der"
cmp "$root/release-public.der" "$root/configured-release-public.der"
"$root/venv/bin/aptl" appliance prepare \
    --release-dir "$root/release" --template "$root/release-template.json"
"$root/venv/bin/aptl" appliance verify-redistribution-review \
    --release-dir "$root/release" \
    --notices-output "$root/publication/THIRD-PARTY-NOTICES.md"
"$root/venv/bin/aptl" appliance seal \
    --release-dir "$root/release" --private-key "$root/release-private.pem" \
    --qualification-public-key "$root/qualification-public.pem"
"$root/venv/bin/aptl" appliance verify \
    --release-dir "$root/release" --public-key "$root/release-public.pem" \
    --qualification-public-key "$root/qualification-public.pem"

manifest_digest=$("$root/venv/bin/python" -c \
    'import json,sys; print(json.load(open(sys.argv[1]))["manifest_digest"])' \
    "$root/release/manifest.sig.json")
release_id="aptl-${APTL_RELEASE_TAG}-x86_64"
"$root/venv/bin/aptl" appliance split-distribution \
    --source "$root/release/artifacts/aptl-golden.qcow2" \
    --output-dir "$root/golden" --release-id "$release_id" \
    --manifest-digest "$manifest_digest" --private-key "$root/release-private.pem"
"$root/venv/bin/aptl" appliance split-distribution \
    --source "$root/release/artifacts/offline-payload.tar" \
    --output-dir "$root/offline" --release-id "$release_id" \
    --manifest-digest "$manifest_digest" --private-key "$root/release-private.pem"

metadata_name="${release_id}.metadata.tar"
tar --create --file "$root/publication/$metadata_name" \
    --exclude=artifacts/aptl-golden.qcow2 \
    --exclude=artifacts/offline-payload.tar \
    --directory "$root/release" .
cp "$root/release-public.pem" "$root/publication/appliance-release-public.pem"
cp "$root/qualification-public.pem" \
    "$root/publication/appliance-qualification-public.pem"
find "$root/golden" "$root/offline" -maxdepth 1 -type f -exec cp {} "$root/publication/" \;
if find "$root/publication" -maxdepth 1 -type f -size +2047M -print -quit | grep -q .; then
    echo 'publication contains an asset at or above the GitHub 2 GiB limit' >&2
    exit 1
fi
rm "$root/release-private.pem"
unset APTL_RELEASE_SIGNING_KEY_PEM
unset APTL_RELEASE_PUBLIC_KEY_PEM APTL_QUALIFICATION_PUBLIC_KEY_PEM
unset APTL_REDISTRIBUTION_REVIEW_JSON
trap - EXIT INT TERM
