#!/usr/bin/env bash
#
# Reproduce the curated-variant live-action proof for one catalog variant (#535/#554).
#
# For the named curated variant this script: (1) sets aptl.json containers to the
# variant's matched profile set, (2) boots it through the PUBLIC start path
# (`uv run aptl lab start --scenario <id>`), (3) captures the canonical
# RangeSnapshot (`aptl lab status --json`), (4) compares the running range to the
# variant's model-derived reduced surface via `aptl.validation.curated_live_proof`,
# (5) drives the TechVault attacker-target participant action through the ACES
# control plane, (6) writes evidence next to this script, and (7) tears the lab
# down and restores aptl.json to its exact pre-run content. It only uses the
# local `uv run aptl` CLI and the tested helper -- no raw docker.
#
# Every lifecycle step is checked: a failed config write, lab start, snapshot
# capture, or comparison fails the proof with a non-zero exit. The proof passes
# only when the lab started cleanly AND the running range matched the expected
# reduced surface. Teardown failure is surfaced as a warning (the verdict is
# already decided) so the operator can clean up by hand.
#
# This is a DESTRUCTIVE, minutes-long maintainer/CI-runner activity (it runs
# `aptl lab stop -v`), not fast CI or pre-commit. It needs Docker with enough
# memory/disk for the variant and a populated `.env` (no placeholder secrets).
#
# Usage:
#   docs/aces/techvault-curated-live-validation-gate/run-curated-live-proof.sh <catalog-id>
#   <catalog-id> in: techvault-observability-core | techvault-defensive-min |
#                    techvault-enterprise-web | techvault-attacker-target
#
set -uo pipefail

CATALOG_ID="${1:-}"
case "$CATALOG_ID" in
  techvault-observability-core) MATCHED='{}' ;;
  techvault-defensive-min)      MATCHED='{"wazuh":true}' ;;
  techvault-enterprise-web)     MATCHED='{"enterprise":true,"wazuh":true}' ;;
  techvault-attacker-target)    MATCHED='{"kali":true,"victim":true,"wazuh":true}' ;;
  *)
    echo "usage: $0 <techvault-observability-core|techvault-defensive-min|techvault-enterprise-web|techvault-attacker-target>" >&2
    exit 2 ;;
esac

# Resolve repo root from this script's location (docs/aces/<gate-dir>/).
EVID_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$EVID_DIR/../../.." && pwd)"
OUT_DIR="$EVID_DIR/$CATALOG_ID"
SCENARIO="scenarios/${CATALOG_ID}.sdl.yaml"
cd "$REPO_ROOT"

fail() { echo "PROOF FAILED ($CATALOG_ID): $*" >&2; exit 1; }

# Snapshot the operator's exact aptl.json so the trap restores byte-for-byte,
# preserving any local edits and not depending on Git or the committed version.
ORIG_CONFIG="$(mktemp)"
cp aptl.json "$ORIG_CONFIG" || fail "could not snapshot aptl.json before editing"
restore_config() {
  if ! cp "$ORIG_CONFIG" aptl.json; then
    echo "WARNING ($CATALOG_ID): failed to restore aptl.json from $ORIG_CONFIG;" \
         "original content is preserved there." >&2
    return
  fi
  rm -f "$ORIG_CONFIG"
}
trap restore_config EXIT

mkdir -p "$OUT_DIR" || fail "could not create evidence dir $OUT_DIR"

# 1. Matched config: enable exactly the variant's container profiles.
if ! uv run python - "$MATCHED" <<'PY'
import json, sys, pathlib
want = json.loads(sys.argv[1])
p = pathlib.Path("aptl.json"); cfg = json.loads(p.read_text())
for k in cfg["containers"]:
    cfg["containers"][k] = bool(want.get(k, False))
p.write_text(json.dumps(cfg, indent=4) + "\n")
PY
then
  fail "could not write matched config"
fi

# 2. Boot through the public start path (timed). A non-zero exit fails the proof.
START=$(date +%s)
uv run aptl lab start --scenario "$CATALOG_ID" > "$OUT_DIR/boot.log" 2>&1
BOOT_RC=$?
ELAPSED=$(( $(date +%s) - START ))
READINESS=$(head -1 "$OUT_DIR/boot.log")
if [ "$BOOT_RC" != "0" ]; then
  uv run aptl lab stop -v -y > "$OUT_DIR/stop.log" 2>&1 || true
  fail "aptl lab start exited $BOOT_RC (see $OUT_DIR/boot.log)"
fi

# 3. Capture the canonical RangeSnapshot. Must be non-empty.
if ! uv run aptl lab status --json > "$OUT_DIR/snapshot.raw.json" 2>/dev/null \
   || [ ! -s "$OUT_DIR/snapshot.raw.json" ]; then
  uv run aptl lab stop -v -y > "$OUT_DIR/stop.log" 2>&1 || true
  fail "could not capture a range snapshot"
fi

# 4. Summarize + compare via the tested helper; for attacker-target, also drive
#    the participant action proof and write participant-action.json. The helper
#    exits non-zero when the range or required participant proof fails.
APTL_CLP_ID="$CATALOG_ID" APTL_CLP_SCENARIO="$SCENARIO" APTL_CLP_MATCHED="$MATCHED" \
APTL_CLP_READINESS="$READINESS" APTL_CLP_ELAPSED="$ELAPSED" \
APTL_CLP_SNAP="$OUT_DIR/snapshot.raw.json" APTL_CLP_OUT="$OUT_DIR" \
uv run python - <<'PY'
import json, os, pathlib
from aptl.core.config import AptlConfig
from aptl.validation.curated_live_proof import (
    compare_to_snapshot,
    expected_reduced_matrix,
    run_participant_action_proof,
    summarize_snapshot,
)
root = pathlib.Path(".").resolve()
matched = json.loads(os.environ["APTL_CLP_MATCHED"])
config = AptlConfig(lab={"name": "techvault"}, containers=matched)
matrix = expected_reduced_matrix(root, config, root / os.environ["APTL_CLP_SCENARIO"])
snapshot = json.loads(pathlib.Path(os.environ["APTL_CLP_SNAP"]).read_text())
ok, diagnostics = compare_to_snapshot(matrix, snapshot)
out = pathlib.Path(os.environ["APTL_CLP_OUT"])
summary = summarize_snapshot(snapshot)
(out / "snapshot.json").write_text(json.dumps(summary, indent=2) + "\n")
participant_action = {
    "verdict": "SKIPPED",
    "reason": "variant does not realize both kali and victim participant-action containers",
}
if os.environ["APTL_CLP_ID"] == "techvault-attacker-target":
    participant_proof = run_participant_action_proof(root, config)
    (out / "participant-action.json").write_text(
        json.dumps(participant_proof, indent=2) + "\n"
    )
    address = str(participant_proof["participant_address"])
    operation_status = participant_proof.get("operation_status") or {}
    behavior = participant_proof.get("participant_behavior_history") or {}
    participant_action = {
        "verdict": participant_proof["verdict"],
        "artifact": "participant-action.json",
        "participant_address": address,
        "operation_id": operation_status.get("operation_id"),
        "operation_state": operation_status.get("state"),
        "behavior_event_count": len(behavior.get(address, [])),
    }
participant_ok = participant_action["verdict"] in {"PASS", "SKIPPED"}
aggregate_ok = ok and participant_ok
result = {
    "catalog_id": os.environ["APTL_CLP_ID"],
    "scenario": pathlib.Path(os.environ["APTL_CLP_SCENARIO"]).name,
    "matched_config_containers": sorted(k for k, v in matched.items() if v),
    "command": f"uv run aptl lab start --scenario {os.environ['APTL_CLP_ID']}",
    "readiness_outcome": os.environ["APTL_CLP_READINESS"].strip(),
    "boot_elapsed_seconds": int(os.environ["APTL_CLP_ELAPSED"]),
    **matrix.to_dict(),
    "actual_containers": sorted(c["name"] for c in summary["containers"] if c.get("name")),
    "actual_networks": sorted(n["name"] for n in summary["networks"] if n.get("name")),
    "participant_action": participant_action,
    "verdict": "PASS" if aggregate_ok else "FAIL",
    "diagnostics": diagnostics,
}
(out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
pathlib.Path(os.environ["APTL_CLP_SNAP"]).unlink(missing_ok=True)
print(f"{os.environ['APTL_CLP_ID']}: {result['verdict']} "
      f"(readiness='{result['readiness_outcome']}', {result['boot_elapsed_seconds']}s)")
for d in diagnostics:
    print("  -", d)
if participant_action["verdict"] != "SKIPPED":
    print(f"participant_action: {participant_action['verdict']} "
          f"({participant_action['behavior_event_count']} behavior events)")
raise SystemExit(0 if aggregate_ok else 1)
PY
CMP_RC=$?

# 5. Tear down (always attempt; the verdict is already decided).
if ! uv run aptl lab stop -v -y > "$OUT_DIR/stop.log" 2>&1; then
  echo "WARNING ($CATALOG_ID): teardown failed (see $OUT_DIR/stop.log); clean up by hand." >&2
fi

[ "$CMP_RC" = "0" ] || fail "running range did not match the expected reduced surface"
echo "PROOF PASSED ($CATALOG_ID)"
