"""Probe backend methods using fake Docker and temporary synthetic files."""

import json
import os
import pathlib
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
from aptl.backends.raes_base_substrate import BaseContainerSpec
from aptl.core.deployment._compose_base_substrate import ComposeBaseSubstrateMixin


class Probe(ComposeBaseSubstrateMixin):
    def __init__(self, root, info):
        self._project_dir = root
        self._project_name = "owned-project"
        self._offline_staged = False
        self.info = info
        self.commands = []

    def container_inspect(self, name):
        return self.info

    def _run(self, argv, **kwargs):
        self.commands.append(argv)
        return SimpleNamespace(returncode=0)

    def _base_container_create_command(self, *args):
        return ["docker", "create", "synthetic-only"]

    def _complete_base_container_start(self, *args):
        pass

    def _project_dotenv(self):
        return {}


with tempfile.TemporaryDirectory(prefix="aptl-review-canary-") as tmp:
    root = pathlib.Path(tmp)
    spec = BaseContainerSpec(
        "nodes.victim",
        "aptl-victim",
        "review-image:1",
        False,
        environment_names=("REVIEW_CANARY",),
    )
    foreign = {
        "State": {"Running": True},
        "Config": {
            "Image": "review-image:1",
            "Labels": {"com.docker.compose.project": "foreign-project"},
        },
    }
    p = Probe(root, foreign)
    adopted = p._base_container_already_realized(spec, spec.image_ref)
    p.info = {
        "State": {"Running": False},
        "Config": {
            "Image": "review-image:other",
            "Labels": {"com.docker.compose.project": "foreign-project"},
        },
    }
    p.start_base_container(spec)
    envpath = root / ".aptl/realization/env/aptl-victim.env"
    with patch.dict(os.environ, {"REVIEW_CANARY": "synthetic-value"}, clear=True):
        p._append_base_environment([], spec)
        inherited = envpath.read_text() == "REVIEW_CANARY=synthetic-value\n"
        victim = root / "synthetic-file"
        victim.write_text("unchanged\n")
        envpath.unlink()
        envpath.symlink_to(victim)
        p._append_base_environment([], spec)
        followed = victim.read_text() != "unchanged\n"
    print(
        json.dumps(
            {
                "foreign_matching_container_adopted": adopted,
                "foreign_container_removal_requested": [
                    "docker",
                    "rm",
                    "-f",
                    "aptl-victim",
                ]
                in p.commands,
                "ambient_canary_bound_without_grant": inherited,
                "generated_env_followed_symlink": followed,
                "daemon_called": False,
                "real_credentials_used": False,
            },
            indent=2,
        )
    )
