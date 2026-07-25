"""Docker Compose image realization helpers."""

from __future__ import annotations

from pathlib import Path

import yaml

from aptl.core.deployment.realization import (
    DeploymentImageRealization,
    DeploymentRealizationSpec,
)
from aptl.core.lab_types import LabResult

_IMAGE_REALIZATION_TIMEOUT = 600
_IMAGE_OVERRIDE_RELATIVE_PATH = Path(".aptl") / "realization" / "compose-images.yml"


class _ResetValue:
    """Marker emitting Compose's ``!reset`` tag (remove the key on merge).

    Compose >= 2.24 rejects ``build: null`` at schema validation, so clearing
    a base service's ``build`` from an override file requires the ``!reset``
    merge tag instead of a null value.
    """


class _ImageOverrideDumper(yaml.SafeDumper):
    """Safe YAML dumper that can emit Compose's ``!reset`` removal tag."""


_ImageOverrideDumper.add_representer(
    _ResetValue,
    lambda dumper, _value: dumper.represent_scalar("!reset", ""),
)


class ComposeRealizationImageMixin:
    """Realize typed scenario image operations through Docker Compose."""

    def _prepare_realization_images(
        self,
        realization: DeploymentRealizationSpec,
    ) -> tuple[LabResult | None, tuple[Path, ...] | None]:
        """Run typed pull/build image operations and write a compose override."""

        if not realization.images:
            return None, None
        for image in realization.images:
            result = self._realize_image(image)
            if result is not None:
                return result, None
        override_path = self._write_image_override(realization.images)
        return None, (self._project_dir / "docker-compose.yml", override_path)

    def _realize_image(
        self,
        image: DeploymentImageRealization,
    ) -> LabResult | None:
        """Run one image operation through this backend's Docker runner."""

        if image.mode == "pull":
            return self._pull_realization_image(image)
        if image.mode == "build":
            return self._build_realization_image(image)
        return LabResult(
            success=False,
            error=f"Unsupported image realization mode for ACES node {image.address}.",
        )

    def _pull_realization_image(
        self,
        image: DeploymentImageRealization,
    ) -> LabResult | None:
        """Pull one scenario-resolved image reference."""

        result = self._run(
            ["docker", "pull", image.image_ref],
            timeout=_IMAGE_REALIZATION_TIMEOUT,
        )
        error = (
            f"Image pull failed for ACES node {image.address}."
            if result.returncode != 0
            else None
        )
        return LabResult(success=False, error=error) if error else None

    def _build_realization_image(
        self,
        image: DeploymentImageRealization,
    ) -> LabResult | None:
        """Build one scenario-resolved local image reference."""

        error = self._build_realization_input_error(image)
        if error is None:
            result = self._run(
                [
                    "docker",
                    "build",
                    "-t",
                    image.image_ref,
                    "-f",
                    str(image.dockerfile_path),
                    str(image.context_path),
                ],
                timeout=_IMAGE_REALIZATION_TIMEOUT,
            )
            error = (
                f"Image build failed for ACES node {image.address}."
                if result.returncode != 0
                else None
            )
        return LabResult(success=False, error=error) if error else None

    @staticmethod
    def _build_realization_input_error(
        image: DeploymentImageRealization,
    ) -> str | None:
        """Return an image-build input error message, if any."""

        return (
            f"Image build input missing for ACES node {image.address}."
            if not image.dockerfile_path or not image.context_path
            else None
        )

    def _write_image_override(
        self,
        images: tuple[DeploymentImageRealization, ...],
    ) -> Path:
        """Write a contained Compose override for scenario-resolved images."""

        override_path = self._project_dir / _IMAGE_OVERRIDE_RELATIVE_PATH
        override_path.parent.mkdir(parents=True, exist_ok=True)
        services = {
            image.service_name: {"image": image.image_ref, "build": _ResetValue()}
            for image in images
        }
        override_path.write_text(
            yaml.dump(
                {"services": services},
                Dumper=_ImageOverrideDumper,
                sort_keys=True,
            ),
            encoding="utf-8",
            newline="\n",
        )
        return override_path

    def _start_with_compose_files(
        self,
        profiles: list[str],
        *,
        build: bool,
        compose_files: tuple[Path, ...],
        exclude_services: tuple[str, ...] = (),
    ) -> LabResult:
        """Start lab services using a generated realization override."""

        cmd = self._build_command("up", profiles, compose_files=compose_files)
        if build:
            cmd.append("--build")
        cmd.append("-d")
        for service in exclude_services:
            cmd += ["--scale", f"{service}=0"]
        result = self._run(cmd)
        if result.returncode != 0:
            return LabResult(success=False, error=result.stderr)
        return LabResult(success=True, message="Lab started")

    def _start_realized_services(
        self,
        profiles: list[str],
        *,
        build: bool,
        compose_files: tuple[Path, ...] | None,
        exclude_services: tuple[str, ...] = (),
    ) -> LabResult:
        """Start services with the generated override when one exists.

        ``exclude_services`` (ADR-048 mixed realization) scales those Compose
        service names to zero: they were already realized directly by the
        generic materializer and must not also start as Compose containers.
        """

        if compose_files is None:
            return self.start(profiles, build=build, exclude_services=exclude_services)
        return self._start_with_compose_files(
            profiles,
            build=build,
            compose_files=compose_files,
            exclude_services=exclude_services,
        )
