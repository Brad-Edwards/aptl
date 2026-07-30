"""Docker Compose image pre-fetch / staged-image verification.

Split out of ``docker_compose.py`` to keep that module within the S104
file-length budget; the behaviour is unchanged. ``pull_images`` pre-pulls (or,
offline, inspects) container images before ``compose up`` so a missing image
fails as a bounded warning rather than mid-start.
"""

from __future__ import annotations

from aptl.utils.logging import get_logger

log = get_logger("deployment.docker_compose")


class ComposeImageFetchMixin:
    """Pre-pull or verify staged container images for the Compose backend."""

    def pull_images(self, images: list[str]) -> list[str]:
        """Pre-pull container images via docker pull.

        Args:
            images: List of image references to pull.

        Returns:
            List of warning messages for images that failed to pull
            (non-fatal).
        """
        warnings: list[str] = []
        for image in images:
            try:
                action = self._image_fetch_action(image)
                result = self._run(action)
                if result.returncode != 0:
                    warnings.append(self._image_fetch_failure(image, result.stderr))
                else:
                    log.info(
                        "%s %s",
                        "Verified staged image" if self._offline_staged else "Pulled",
                        image,
                    )
            except OSError as exc:
                msg = self._image_fetch_exception(image, exc)
                log.warning(msg)
                warnings.append(msg)
        return warnings

    def _image_fetch_action(self, image: str) -> list[str]:
        """Return the staged inspection or online pull command for one image."""

        if self._offline_staged:
            return ["docker", "image", "inspect", image]
        return ["docker", "pull", image]

    def _image_fetch_failure(self, image: str, stderr: str) -> str:
        """Return and log one bounded image verification failure."""

        if self._offline_staged:
            message = f"Required staged image is missing: {image}"
        else:
            message = f"Failed to pull {image}: {stderr.strip()}"
        log.warning(message)
        return message

    def _image_fetch_exception(self, image: str, exc: OSError) -> str:
        """Return one image operation failure caused by a local tool error."""

        if self._offline_staged:
            return f"Required staged image could not be inspected: {image}"
        return f"Failed to pull {image}: {exc}"
