"""Behavioral tests for the participant-invoked MISP seed script."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SEED_SCRIPT = PROJECT_ROOT / "scripts" / "seed-misp.sh"


def test_existing_event_in_misp_response_envelope_is_reused(tmp_path):
    """MISP's restSearch response is an object containing ``response``."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    call_log = tmp_path / "curl-calls"
    fake_curl = fake_bin / "curl"
    fake_curl.write_text(
        """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

args = sys.argv[1:]
method = args[args.index("-X") + 1]
url = args[-1]
with pathlib.Path(os.environ["APTL_TEST_CURL_LOG"]).open("a") as log:
    log.write(f"{method} {url}\\n")

if url.endswith("/events/restSearch"):
    print(json.dumps({"response": [{"Event": {"id": "42", "uuid": "event-42"}}]}))
elif "/attributes/add/42" in url:
    print(json.dumps({"Attribute": {"id": "1"}}))
elif url.endswith("/tags/attachTagToObject"):
    print(json.dumps({"success": "Event tagged successfully"}))
elif url.endswith("/events"):
    print(json.dumps({"Event": {"id": "99", "uuid": "unexpected-new-event"}}))
else:
    raise SystemExit(2)
""",
        encoding="utf-8",
    )
    fake_curl.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "APTL_TEST_CURL_LOG": str(call_log),
        "MISP_API_KEY": "test-key",
        "MISP_URL": "https://misp.invalid",
        "MISP_CACERT": str(tmp_path / "missing-ca.pem"),
    }

    result = subprocess.run(
        [SEED_SCRIPT],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )

    assert result.returncode == 0, result.stderr
    assert "Event already exists (id: 42" in result.stdout
    calls = call_log.read_text(encoding="utf-8").splitlines()
    assert "POST https://misp.invalid/events" not in calls
