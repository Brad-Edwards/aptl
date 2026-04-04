"""Deployment backend abstraction layer.

Provides a pluggable deployment backend for lab lifecycle management.
The default backend is Docker Compose; additional backends (SSH remote,
Kubernetes, etc.) can be selected via the ``deployment.provider`` field
in aptl.json.

Usage::

    from aptl.core.config import load_config
    from aptl.core.deployment import get_backend

    config = load_config(Path("aptl.json"))
    backend = get_backend(config, project_dir=Path("."))
    result = backend.start(profiles=["wazuh", "victim", "kali"])
"""

from pathlib import Path

from aptl.core.deployment.backend import DeploymentBackend
from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.deployment.ssh_compose import SSHComposeBackend

__all__ = [
    "DeploymentBackend",
    "DockerComposeBackend",
    "SSHComposeBackend",
    "get_backend",
]


def get_backend(config: "AptlConfig", project_dir: Path) -> DeploymentBackend:  # noqa: F821
    """Create a deployment backend from configuration.

    Reads ``config.deployment.provider`` to select the backend:
    - ``"docker-compose"`` (default): Local Docker Compose
    - ``"ssh-compose"``: Remote Docker Compose over SSH

    Args:
        config: Validated APTL configuration.
        project_dir: Working directory for the deployment.

    Returns:
        A DeploymentBackend instance.

    Raises:
        ValueError: If the provider is not recognized or required
            fields are missing.
    """
    from aptl.core.config import AptlConfig  # avoid circular import

    provider = config.deployment.provider
    project_name = config.deployment.project_name

    if provider == "docker-compose":
        return DockerComposeBackend(
            project_dir=project_dir,
            project_name=project_name,
        )

    if provider == "ssh-compose":
        dep = config.deployment
        if not dep.ssh_host:
            raise ValueError(
                "deployment.ssh_host is required for ssh-compose provider"
            )
        if not dep.ssh_user:
            raise ValueError(
                "deployment.ssh_user is required for ssh-compose provider"
            )
        return SSHComposeBackend(
            project_dir=project_dir,
            host=dep.ssh_host,
            user=dep.ssh_user,
            ssh_key=dep.ssh_key,
            ssh_port=dep.ssh_port,
            remote_dir=dep.remote_dir,
            project_name=project_name,
        )

    raise ValueError(
        f"Unknown deployment provider: {provider!r}. "
        f"Supported: 'docker-compose', 'ssh-compose'"
    )
