#!/usr/bin/env bash
set -euo pipefail

: "${APTL_CANDIDATE_PUBLICATION:?candidate publication directory is required}"
: "${APTL_QUALIFICATION_OUTPUT:?qualification output path is required}"
: "${APTL_QUALIFICATION_SEATS:?qualification seat count is required}"

case "$APTL_QUALIFICATION_SEATS" in
    1|2) ;;
    *) echo 'qualification seat count must be one or two' >&2; exit 2 ;;
esac
for client in claude codex; do
    if ! command -v "$client" >/dev/null 2>&1; then
        echo "qualification runner is missing the authenticated $client CLI" >&2
        exit 2
    fi
done

work=$PWD/build/appliance-qualification
test ! -e "$work"
install -d -m 0700 "$work" "$work/candidate" "$work/receipts"

python3 - "$APTL_CANDIDATE_PUBLICATION/candidate-metadata.tar" "$work/candidate" <<'PYTHON'
import pathlib
import tarfile
import sys

archive_path = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
with tarfile.open(archive_path, "r:") as archive:
    archive.extractall(destination, filter="data")
PYTHON

python3 -m venv "$work/venv"
"$work/venv/bin/pip" install --require-hashes -r requirements/ci.txt
"$work/venv/bin/pip" install --require-hashes -r requirements/runtime.txt
"$work/venv/bin/pip" install --no-deps .

reconstruct() {
    local directory=$1
    local output=$2
    local index signature
    index=$(find "$APTL_CANDIDATE_PUBLICATION/$directory" -maxdepth 1 -type f \
        -name '*.distribution.json' -print -quit)
    signature=$(find "$APTL_CANDIDATE_PUBLICATION/$directory" -maxdepth 1 -type f \
        -name '*.distribution.sig.json' -print -quit)
    test -n "$index" -a -n "$signature"
    "$work/venv/bin/aptl" appliance reconstruct-distribution \
        --index "$index" --signature "$signature" \
        --chunks-dir "$APTL_CANDIDATE_PUBLICATION/$directory" \
        --public-key "$work/candidate/candidate-public.pem" \
        --output "$work/candidate/$output"
}
reconstruct golden aptl-golden.qcow2
reconstruct offline offline-payload.tar

readarray -t candidate_identity < <("$work/venv/bin/python" - "$work/candidate" <<'PYTHON'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
manifest = json.loads((root / "candidate-manifest.json").read_bytes())
signature = json.loads((root / "candidate-manifest.sig.json").read_bytes())
golden = next(item for item in manifest["artifacts"] if item["kind"] == "golden-disk")
print(manifest["candidate_id"])
print(signature["manifest_digest"])
print(golden["sha256"])
PYTHON
)
candidate_id=${candidate_identity[0]}
candidate_manifest_digest=${candidate_identity[1]}
golden_image_digest=${candidate_identity[2]}

seat_roots=()
start_pids=()
client_keys=()
cleanup() {
    if test -n "${sampler_pid:-}"; then
        kill "$sampler_pid" >/dev/null 2>&1 || true
    fi
    for seat_root in "${seat_roots[@]}"; do
        "$work/venv/bin/aptl" seat stop --seat-root "$seat_root" >/dev/null 2>&1 || true
    done
    rm -f "$work/qualification-private.pem"
    for identity in "${client_keys[@]}"; do
        rm -f "$identity" "$identity.pub"
    done
}
trap cleanup EXIT INT TERM

resource_arguments=(
    scripts/appliance/sample-seat-resources.py
    --stop-file "$work/resource-sampling.stop"
    --output "$work/evidence/resource-sample.json"
)
for index in $(seq 1 "$APTL_QUALIFICATION_SEATS"); do
    resource_arguments+=(--seat-root "$work/seat-${index}")
done
"$work/venv/bin/python" "${resource_arguments[@]}" &
sampler_pid=$!

cold_started=$(date +%s)
for index in $(seq 1 "$APTL_QUALIFICATION_SEATS"); do
    seat_id="seat-${index}"
    seat_root="$work/$seat_id"
    release_dir="$seat_root/launch/release"
    project="$work/client-$seat_id"
    identity="$work/client-key-$index"
    install -d -m 0700 "$seat_root/launch" "$project"
    cp -al "$work/candidate" "$release_dir"
    seat_roots+=("$seat_root")
    ssh-keygen -q -t ed25519 -N '' -f "$identity"
    client_keys+=("$identity")
    participant_port=$((13000 + index))
    recovery_port=$((14000 + index))
    mcp_port=$((15000 + index))
    "$work/venv/bin/aptl" seat start \
        --seat-root "$seat_root" --seat-id "$seat_id" \
        --release-dir "$release_dir" \
        --release-public-key "$release_dir/candidate-public.pem" \
        --qualification-public-key "$release_dir/candidate-public.pem" \
        --mapping "participant,tcp,127.0.0.1,$participant_port,127.0.0.1,3000" \
        --mapping "recovery,tcp,127.0.0.1,$recovery_port,127.0.0.1,8400" \
        --mapping "host-mcp,tcp,127.0.0.1,$mcp_port,127.0.0.1,2222" \
        --access-owner "qualification-$index" \
        --access-public-key "$identity.pub" \
        --access-identity-file "$identity" \
        --access-project-dir "$project" \
        --access-profile red --access-client claude --access-client codex \
        --qualification-candidate >"$work/$seat_id.start.json" &
    start_pids+=("$!")
done

for pid in "${start_pids[@]}"; do
    wait "$pid"
done
cold_start_seconds=$(($(date +%s) - cold_started))

install -d -m 0700 "$work/evidence"
cp "$work/seat-1/access/generation-1/runtime-evidence.json" \
    "$work/evidence/runtime-evidence.json"
if test "$APTL_QUALIFICATION_SEATS" = 2; then
    "$work/venv/bin/python" scripts/appliance/probe-participant-browser.py \
        --runtime-evidence "$work/evidence/runtime-evidence.json" \
        --readiness "$work/candidate/participant-readiness.json" \
        --participant-url http://127.0.0.1:13001/ \
        --participant-url http://127.0.0.1:13002/ \
        --output "$work/evidence/browser-probe.json"
fi

cp -al "$work/candidate" "$work/failed-candidate"
rm "$work/failed-candidate/boundary-policy.json"
cp "$work/candidate/boundary-policy.json" \
    "$work/failed-candidate/boundary-policy.json"
chmod 0600 "$work/failed-candidate/boundary-policy.json"
printf '\n' >>"$work/failed-candidate/boundary-policy.json"
if "$work/venv/bin/aptl" appliance verify-candidate \
    --candidate-dir "$work/failed-candidate" \
    --public-key "$work/candidate/candidate-public.pem"
then
    echo 'modified candidate unexpectedly verified' >&2
    exit 1
fi

reset_started=$(date +%s)

for index in $(seq 1 "$APTL_QUALIFICATION_SEATS"); do
    seat_id="seat-${index}"
    seat_root="$work/$seat_id"
    release_dir="$seat_root/launch/release"
    project="$work/client-$seat_id"
    for client in claude codex; do
        if test "$client" = claude; then
            config="$project/.mcp.json"
        else
            config="$project/.codex/config.toml"
        fi
        "$work/venv/bin/python" scripts/appliance/probe-native-client.py \
            --mode active --client "$client" --config "$config" \
            --state "$work/receipts/$seat_id-$client.active.json" \
            --candidate-id "$candidate_id" \
            --candidate-manifest-digest "$candidate_manifest_digest" \
            --golden-image-digest "$golden_image_digest" \
            --seat-id "$seat_id" --generation 1
    done
    "$work/venv/bin/aptl" seat stop --seat-root "$seat_root"
    for client in claude codex; do
        if test "$client" = claude; then
            config="$project/.mcp.json"
        else
            config="$project/.codex/config.toml"
        fi
        "$work/venv/bin/python" scripts/appliance/probe-native-client.py \
            --mode revoked --client "$client" --config "$config" \
            --state "$work/receipts/$seat_id-$client.active.json" \
            --receipt "$work/receipts/$seat_id-$client.json" \
            --candidate-id "$candidate_id" \
            --candidate-manifest-digest "$candidate_manifest_digest" \
            --golden-image-digest "$golden_image_digest" \
            --seat-id "$seat_id" --generation 1
    done
    "$work/venv/bin/aptl" seat reset \
        --seat-root "$seat_root" --seat-id "$seat_id" \
        --release-dir "$release_dir" \
        --release-public-key "$release_dir/candidate-public.pem" \
        --qualification-public-key "$release_dir/candidate-public.pem"
done
clean_reset_seconds=$(($(date +%s) - reset_started))

failed_arguments=(
    scripts/appliance/write-failed-candidate-proof.py
    --candidate-dir "$work/candidate"
    --failed-candidate-dir "$work/failed-candidate"
    --public-key "$work/candidate/candidate-public.pem"
    --output "$work/evidence/failed-candidate.json"
)
for state in "$work"/receipts/seat-*.active.json; do
    failed_arguments+=(--active-state "$state")
done
"$work/venv/bin/python" "${failed_arguments[@]}"

warm_started=$(date +%s)
"$work/venv/bin/aptl" seat start \
    --seat-root "$work/seat-1" --seat-id seat-1 \
    --release-dir "$work/seat-1/launch/release" \
    --release-public-key "$work/seat-1/launch/release/candidate-public.pem" \
    --qualification-public-key "$work/seat-1/launch/release/candidate-public.pem" \
    --mapping "participant,tcp,127.0.0.1,13001,127.0.0.1,3000" \
    --mapping "recovery,tcp,127.0.0.1,14001,127.0.0.1,8400" \
    --mapping "host-mcp,tcp,127.0.0.1,15001,127.0.0.1,2222" \
    --access-owner qualification-1 \
    --access-public-key "$work/client-key-1.pub" \
    --access-identity-file "$work/client-key-1" \
    --access-project-dir "$work/client-seat-1" \
    --access-profile red --access-client claude --access-client codex \
    --qualification-candidate >"$work/seat-1.recovery.json"
warm_start_seconds=$(($(date +%s) - warm_started))
"$work/venv/bin/aptl" seat stop --seat-root "$work/seat-1"
second_reset_started=$(date +%s)
"$work/venv/bin/aptl" seat reset \
    --seat-root "$work/seat-1" --seat-id seat-1 \
    --release-dir "$work/seat-1/launch/release" \
    --release-public-key "$work/seat-1/launch/release/candidate-public.pem" \
    --qualification-public-key "$work/seat-1/launch/release/candidate-public.pem"
clean_reset_seconds=$((clean_reset_seconds + $(date +%s) - second_reset_started))

: >"$work/resource-sampling.stop"
wait "$sampler_pid"
sampler_pid=
"$work/venv/bin/python" scripts/appliance/measure-offline-assets.py \
    --payload "$work/candidate/offline-payload.tar" \
    --output "$work/evidence/asset-sample.json"
"$work/venv/bin/python" scripts/appliance/write-qualification-measurements.py \
    --resource-sample "$work/evidence/resource-sample.json" \
    --asset-sample "$work/evidence/asset-sample.json" \
    --cold-start-seconds "$cold_start_seconds" \
    --warm-start-seconds "$warm_start_seconds" \
    --clean-reset-seconds "$clean_reset_seconds" \
    --output "$work/evidence/measurements.json"

arguments=(
    appliance record-machine-drill
    --candidate-dir "$work/candidate"
    --candidate-public-key "$work/candidate/candidate-public.pem"
    --failed-candidate-receipt "$work/evidence/failed-candidate.json"
    --output "$APTL_QUALIFICATION_OUTPUT"
)
for seat_root in "${seat_roots[@]}"; do
    arguments+=(--seat-root "$seat_root")
done
for receipt in "$work"/receipts/seat-*.json; do
    arguments+=(--probe-receipt "$receipt")
done
"$work/venv/bin/aptl" "${arguments[@]}"

if test "$APTL_QUALIFICATION_SEATS" = 2; then
    : "${APTL_QUALIFICATION_SIGNING_KEY_PEM:?qualification signing key is required on machine A}"
    printf '%s' "$APTL_QUALIFICATION_SIGNING_KEY_PEM" >"$work/qualification-private.pem"
    chmod 0600 "$work/qualification-private.pem"
    qualification_arguments=(
        appliance build-participant-qualification
        --candidate-dir "$work/candidate"
        --candidate-public-key "$work/candidate/candidate-public.pem"
        --runtime-evidence "$work/evidence/runtime-evidence.json"
        --browser-probe "$work/evidence/browser-probe.json"
        --measurements "$work/evidence/measurements.json"
        --qualification-private-key "$work/qualification-private.pem"
        --output-dir "$work/evidence/participant-qualification"
    )
    for receipt in "$work"/receipts/seat-*.json; do
        qualification_arguments+=(--client-receipt "$receipt")
    done
    "$work/venv/bin/aptl" "${qualification_arguments[@]}"
    rm "$work/qualification-private.pem"
    unset APTL_QUALIFICATION_SIGNING_KEY_PEM
fi
for identity in "${client_keys[@]}"; do
    rm -f "$identity" "$identity.pub"
done
client_keys=()
trap - EXIT INT TERM
