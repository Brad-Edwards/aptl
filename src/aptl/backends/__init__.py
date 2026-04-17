"""APTL backend implementations.

Concrete provisioners, orchestrators, and evaluators for
specific deployment targets. These depend on ``aptl.core.runtime``
protocols and are APTL-specific (not part of the generic SDL or
runtime packages).
"""

from aptl.core.runtime.registry import BackendRegistry

_registry = BackendRegistry()


def get_backend_registry() -> BackendRegistry:
    """Return the shared backend registry with all built-in backends."""
    return _registry


def _register_builtin_backends() -> None:
    """Register stub and docker backends."""
    from aptl.backends.stubs import create_stub_manifest, create_stub_components

    if not _registry.is_registered("stub"):
        _registry.register("stub", create_stub_manifest, create_stub_components)

    from aptl.backends.docker import create_docker_manifest, create_docker_components

    if not _registry.is_registered("docker"):
        _registry.register("docker", create_docker_manifest, create_docker_components)


_register_builtin_backends()
