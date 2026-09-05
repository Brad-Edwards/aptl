"""Reproduce process-boundary defects with harmless local children."""

import json
import os
import pathlib
import signal
import sys
import time
from aptl.workbench.process import BoundedProcessRunner

runner = BoundedProcessRunner()
t0 = time.monotonic()
nonreader = runner.run(
    (sys.executable, "-c", "import time; time.sleep(2)"),
    env={"PATH": "/usr/bin:/bin"},
    cwd=pathlib.Path("/tmp"),
    stdin=b"x" * 200000,
    timeout_seconds=0.2,
    max_output_bytes=1000,
)
latency = round(time.monotonic() - t0, 3)
child_code = """
import subprocess
import sys

child = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(20)"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
print(child.pid, flush=True)
"""
r = runner.run(
    (sys.executable, "-c", child_code),
    env={"PATH": "/usr/bin:/bin"},
    cwd=pathlib.Path("/tmp"),
    stdin=b"",
    timeout_seconds=1,
    max_output_bytes=1000,
)
pid = int(r.stdout)
alive = False
cleanup = "child already gone"
try:
    os.kill(pid, 0)
    alive = True
except ProcessLookupError:
    pass
finally:
    try:
        os.kill(pid, signal.SIGKILL)
        cleanup = "SIGKILL sent"
    except ProcessLookupError:
        pass
print(
    json.dumps(
        {
            "stdin_timeout_seconds": 0.2,
            "elapsed_seconds": latency,
            "stdin_nonreader_returned_success": nonreader.returncode == 0,
            "descendant_alive_after_success": r.returncode == 0 and alive,
            "synthetic_descendant_cleanup": cleanup,
        },
        indent=2,
    )
)
