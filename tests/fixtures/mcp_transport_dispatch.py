"""Transport test adapter: real admission/relay/MCP, synthetic lab observation.

This executable is confined to tests. It never connects to Docker or starts a
lab. Only the runtime observation and process launch dependencies are replaced;
SSH key binding, role admission, revocation and the protocol relay are unchanged.
"""

import json
import os
from pathlib import Path

from aptl.workbench import guest_binding


def observe(binding):
    return json.loads((binding.project_dir / "observation.json").read_text())


def launch(admission):
    admission.authorize()
    launch_data = json.loads(
        (admission.binding.project_dir / "processes.json").read_text()
    )[admission.server.server_id]
    return (
        tuple(launch_data["argv"]),
        Path(launch_data["cwd"]),
        launch_data["env"],
    )


if __name__ == "__main__":
    from aptl.cli.main import app

    guest_binding.observe_guest = observe
    guest_binding.GuestAdmission.launch = launch
    # Provider authentication and the user's environment never enter the MCP.
    os.environ.pop("DOCKER_HOST", None)
    app()
