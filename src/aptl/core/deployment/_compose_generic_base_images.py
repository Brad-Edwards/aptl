"""Building the generic base images an image-free node is realized onto.

ADR-048 realizes a node onto a generic base-OS container, never an appliance
image. The service-manager base images are built from Dockerfiles this
repository ships, so they are built here on every start rather than trusted
because a tag happens to be present locally — a present ``aptl/...:latest``
says nothing about which release built it (issue #1006). Docker's layer cache
makes the unchanged case a no-op.

Split out of ``_compose_base_substrate`` so the build catalog and the container
mechanics each stay inside a file a reader can hold in their head.
"""

from __future__ import annotations

# Every OS-family/service-manager combination `base_image_for_os`
# (src/aptl/backends/raes_materializer.py) can select for a runs_services
# node, mapped to the checked-in Dockerfile that builds it. These are the
# ONLY generic base images that need a local build: the non-service images
# (debian:13-slim, rockylinux:9) are real registry images `docker run`
# already pulls on demand. Never built anywhere in the codebase before
# issue #581 surfaced it via a fresh-machine boot (a developer's existing
# local image cache had silently masked the gap since ADR-048 shipped).
_GENERIC_BASE_IMAGE_BUILDS: dict[str, tuple[str, str]] = {
    # Backend apparatus relay for declared operator interactive access (issue
    # #1006). Not a scenario substrate, but built the same way and on the same
    # freshness terms: from its current Dockerfile on every start.
    "aptl/operator-access-proxy:latest": (
        "containers/operator-access-proxy/Dockerfile",
        ".",
    ),
    "aptl/generic-systemd-base-debian:latest": (
        "containers/generic-systemd-base-debian/Dockerfile",
        ".",
    ),
    "aptl/generic-systemd-base:latest": (
        "containers/generic-systemd-base/Dockerfile",
        "containers/generic-systemd-base",
    ),
    "aptl/generic-systemd-node22-base:latest": (
        "containers/generic-systemd-node22-base/Dockerfile",
        "containers/generic-systemd-node22-base",
    ),
    "aptl/generic-samba-ad-base:latest": (
        "containers/generic-samba-ad-base/Dockerfile",
        "containers/generic-samba-ad-base",
    ),
    "aptl/generic-wazuh-agent-base-debian:latest": (
        "containers/generic-wazuh-agent-base-debian/Dockerfile",
        ".",
    ),
    "aptl/generic-systemd-wazuh-agent-base-debian:latest": (
        "containers/generic-systemd-wazuh-agent-base-debian/Dockerfile",
        ".",
    ),
    "aptl/generic-systemd-wazuh-agent-base:latest": (
        "containers/generic-systemd-wazuh-agent-base/Dockerfile",
        ".",
    ),
    "aptl/generic-samba-ad-wazuh-agent-base:latest": (
        "containers/generic-samba-ad-wazuh-agent-base/Dockerfile",
        ".",
    ),
}

_GENERIC_BASE_IMAGE_DEPENDENCIES: dict[str, str] = {
    "aptl/generic-systemd-wazuh-agent-base-debian:latest": (
        "aptl/generic-systemd-base-debian:latest"
    ),
    "aptl/generic-systemd-wazuh-agent-base:latest": "aptl/generic-systemd-base:latest",
    "aptl/generic-samba-ad-wazuh-agent-base:latest": "aptl/generic-samba-ad-base:latest",
}


class ComposeGenericBaseImageMixin(object):
    """Build the locally-built generic base images, or say why not.

    Mixed into ``DockerComposeBackend``, which supplies ``_run``,
    ``_project_dir`` and ``_offline_staged``.
    """

    def ensure_generic_base_image(self, image_ref: str) -> list[str]:
        """Build a locally-built generic base image from its current Dockerfile.

        A no-op for any image not in ``_GENERIC_BASE_IMAGE_BUILD_CONTEXTS``
        (a real registry reference like ``debian:13-slim`` needs no local
        build; ``docker run`` pulls it on demand).

        The build runs on every start rather than only when the tag is absent:
        ``aptl/...:latest`` being present says nothing about whether it was
        built from the Dockerfile this release ships. Skipping on presence
        pinned every existing install to whatever substrate it first built, so
        an advanced base image, a new package, or a security fix in a layer
        never reached anyone who had already started a lab (issue #1006).
        Docker's layer cache makes the unchanged case a fast no-op, and a
        changed Dockerfile is what actually triggers work.

        Offline staged mode still refuses to build: there the staged image is
        the authority and a missing one is an error, not something to rebuild.
        """

        build = _GENERIC_BASE_IMAGE_BUILDS.get(image_ref)
        if build is None and not self._offline_staged:
            return []
        dependency = _GENERIC_BASE_IMAGE_DEPENDENCIES.get(image_ref)
        failures = (
            self.ensure_generic_base_image(dependency) if dependency is not None else []
        )
        if not failures:
            failures = (
                self._staged_base_image_present(image_ref)
                if self._offline_staged
                else self._build_generic_base_image(image_ref, build)
            )
        return failures

    def _staged_base_image_present(self, image_ref: str) -> list[str]:
        """Offline staged: the staged image is the authority, never rebuilt."""

        inspected = self._run(["docker", "image", "inspect", image_ref], timeout=30)
        if inspected.returncode != 0:
            return [f"required staged generic base image is missing: {image_ref}"]
        return []

    def _build_generic_base_image(
        self, image_ref: str, build: tuple[str, str] | None
    ) -> list[str]:
        """Build the image from the Dockerfile this release ships."""

        if build is None:
            return []
        dockerfile, build_context = build
        built = self._run(
            [
                "docker",
                "build",
                "-t",
                image_ref,
                "-f",
                str(self._project_dir / dockerfile),
                str(self._project_dir / build_context),
            ],
            timeout=600,
        )
        if built.returncode != 0:
            return [f"failed to build generic base image {image_ref}"]
        return []
