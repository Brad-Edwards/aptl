"""Docker Compose image realization helpers."""

from __future__ import annotations

from pathlib import Path

import yaml

from aptl.core.deployment._compose_node_generation import base_compose_file
from aptl.core.deployment.realization import (
    DeploymentImageRealization,
    DeploymentRealizationSpec,
)
from aptl.core.lab_types import LabResult

_IMAGE_REALIZATION_TIMEOUT = 600
_IMAGE_OVERRIDE_RELATIVE_PATH = Path(".aptl") / "realization" / "compose-images.yml"
# Digest domain prefix every locally read image id / manifest digest carries.
_SHA256_PREFIX = "sha256:"


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
        scenario_root: Path,
    ) -> tuple[LabResult | None, tuple[Path, ...] | None]:
        """Run typed pull/build image operations and write a compose override.

        The base Compose file and the generated image override are
        scenario-declared inputs anchored to ``scenario_root`` (issue #874).
        """

        if not realization.images:
            return None, None
        for image in realization.images:
            result = (
                self._verify_staged_image(image)
                if self._offline_staged
                else self._realize_image(image)
            )
            if result is not None:
                return result, None
        override_path = self._write_image_override(realization.images, scenario_root)
        base = base_compose_file(realization, scenario_root)
        return None, (base, override_path)

    def artifact_available(
        self, image_ref: str, *, allow_remote: bool | None = None
    ) -> bool:
        """Whether one immutable artifact reference can be obtained.

        This is the backend half of the RAES artifact availability trust
        boundary (ADR-051). It reports an operational fact only; it never
        pulls, tags, or otherwise mutates state, and it never decides
        admission. The caller partitions the answer by compiled address and
        hands it to RAES planning as trusted facts.

        A locally present reference always counts. A registry-resolvable
        reference counts only when remote acquisition is allowed, which it is
        not for an offline/staged appliance where backend preparation may not
        pull. ``allow_remote`` defaults to this backend's own staging mode so
        callers never have to reach into it; pass it explicitly only to force
        one branch.
        """

        if allow_remote is None:
            allow_remote = not self._offline_staged
        present = self._run(
            ["docker", "image", "inspect", image_ref],
            timeout=_IMAGE_REALIZATION_TIMEOUT,
        )
        if present.returncode == 0:
            return True
        if not allow_remote:
            return False
        resolvable = self._run(
            ["docker", "manifest", "inspect", image_ref],
            timeout=_IMAGE_REALIZATION_TIMEOUT,
        )
        return resolvable.returncode == 0

    def materialize_component_image(
        self, image_ref: str, dockerfile_path: str, context_path: str
    ) -> str | None:
        """Build one component image and return the digest it materialized to.

        This runs during backend preparation, which is the timing the
        per-component build profile declares. It produces a local artifact only;
        no lab state is touched. Building here is what makes the resulting
        digest knowable, so it can enter the processor-owned verified integrity
        set before the runtime gate checks the satisfaction disclosure against
        it. A built image's digest cannot be predicted, because Docker builds are
        not bit-reproducible.

        Idempotent in practice: a repeat build is served from the layer cache.
        Returns nothing when the build fails or the digest cannot be read, so the
        specification is reported unavailable rather than assumed good.
        """

        build = self._run(
            [
                "docker",
                "build",
                "-t",
                image_ref,
                "-f",
                dockerfile_path,
                context_path,
            ],
            timeout=_IMAGE_REALIZATION_TIMEOUT,
        )
        if build.returncode != 0:
            return None
        return self._image_digest(image_ref)

    def _image_digest(self, image_ref: str) -> str | None:
        """Return the sha256 identity of a local image reference."""

        inspect = self._run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image_ref],
            timeout=_IMAGE_REALIZATION_TIMEOUT,
        )
        if inspect.returncode != 0:
            return None
        digest = inspect.stdout.strip()
        return digest if digest.startswith(_SHA256_PREFIX) else None

    def container_image_digest(self, container_name: str) -> str | None:
        """Return the manifest digest of the image backing one container.

        This is the read-after-write half of artifact realization: it reports
        what the container is *actually* running, so the satisfaction disclosure
        is built from the observed digest rather than the planned one. A node
        whose digest cannot be read returns None, which surfaces as a refused
        disclosure rather than an assumed match.
        """

        container = self._run(
            ["docker", "inspect", "--format", "{{.Image}}", container_name],
            timeout=_IMAGE_REALIZATION_TIMEOUT,
        )
        if container.returncode != 0:
            return None
        image_id = container.stdout.strip()
        if not image_id:
            return None
        return self._image_manifest_digest(image_id)

    def substrate_image_identity(self, image_ref: str) -> tuple[str, str] | None:
        """Return the ``(config-id digest, media_type)`` of a locally present ref.

        Route-3 (dynamic-composition) availability is a strict local-lookup: it
        verifies the generic substrate is on the target daemon and never pulls or
        manifest-inspects a registry (ADR-051 route 3). The identity is the image
        **config id** -- the one digest domain whose media type is locally
        knowable and that exactly matches the container's ``{{.Image}}`` readback
        (:meth:`container_image_config_id`), so availability and post-realization
        satisfaction compare like with like. A registry RepoDigest is deliberately
        not used: it may name a Docker (not OCI) manifest, and multiple
        RepoDigests are ambiguous (issue #876 review).
        """

        image_id = self._image_digest(image_ref)
        if image_id is None:
            return None
        return image_id, "application/vnd.oci.image.config.v1+json"

    def container_image_config_id(self, container_name: str) -> str | None:
        """Return the config-id digest of the image backing one container.

        The same digest domain :meth:`substrate_image_identity` reports for an
        image ref, so a dynamic-composition node's realized substrate is compared
        like with like at the runtime gate. Returns None when it cannot be read (a
        refused disclosure, not an assumed match).
        """

        container = self._run(
            ["docker", "inspect", "--format", "{{.Image}}", container_name],
            timeout=_IMAGE_REALIZATION_TIMEOUT,
        )
        if container.returncode != 0:
            return None
        image_id = container.stdout.strip()
        return image_id if image_id.startswith(_SHA256_PREFIX) else None

    def _image_manifest_digest(self, image_id: str) -> str | None:
        """Return an image's registry manifest digest, or its id as a fallback.

        A pulled image is identified by the manifest digest carried in
        ``RepoDigests``, which is what an authored exact pin names. A locally
        built image has no such digest, so its identity is the image id itself.
        """

        references = self._repo_digest_references(image_id)
        if references is None:
            return None
        digest = next(
            (
                reference.rsplit("@", 1)[1]
                for reference in references
                if isinstance(reference, str) and "@sha256:" in reference
            ),
            None,
        )
        return digest or (image_id if image_id.startswith(_SHA256_PREFIX) else None)

    def _repo_digest_references(self, image_id: str) -> list[object] | None:
        """Return an image's ``RepoDigests`` list, or None when it is unreadable."""

        repo_digests = self._run(
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{json .RepoDigests}}",
                image_id,
            ],
            timeout=_IMAGE_REALIZATION_TIMEOUT,
        )
        if repo_digests.returncode != 0:
            return None
        try:
            references = yaml.safe_load(repo_digests.stdout.strip()) or []
        except yaml.YAMLError:
            return None
        return references if isinstance(references, list) else None

    def _verify_staged_image(
        self,
        image: DeploymentImageRealization,
    ) -> LabResult | None:
        """Fail closed when an offline appliance did not stage an exact image."""

        result = self._run(
            ["docker", "image", "inspect", image.image_ref],
            timeout=_IMAGE_REALIZATION_TIMEOUT,
        )
        if result.returncode == 0:
            return None
        return LabResult(
            success=False,
            error=f"Staged image missing for RAES node {image.address}.",
        )

    def _realize_image(
        self,
        image: DeploymentImageRealization,
    ) -> LabResult | None:
        """Run one image operation through this backend's Docker runner."""

        if image.mode == "pull":
            return self._pull_realization_image(image)
        if image.mode == "build":
            return self._realize_build_image(image)
        return LabResult(
            success=False,
            error=f"Unsupported image realization mode for RAES node {image.address}.",
        )

    def _realize_build_image(
        self,
        image: DeploymentImageRealization,
    ) -> LabResult | None:
        """Build one image, or verify a component already materialized upstream."""

        if image.policy_rule == "authored-materialization-specification":
            # Already materialized during backend preparation, which is the
            # timing the per-component build profile declares. Rebuilding
            # here would produce a second image whose digest may differ from
            # the one that entered the verified integrity set, so the
            # satisfaction disclosure would no longer match. Verify presence
            # instead: exactly one build per artifact.
            return self._verify_staged_image(image)
        return self._build_realization_image(image)

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
            f"Image pull failed for RAES node {image.address}."
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
                f"Image build failed for RAES node {image.address}."
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
            f"Image build input missing for RAES node {image.address}."
            if not image.dockerfile_path or not image.context_path
            else None
        )

    @staticmethod
    def _write_image_override(
        images: tuple[DeploymentImageRealization, ...],
        scenario_root: Path,
    ) -> Path:
        """Write a contained Compose override for scenario-resolved images.

        The override is a scenario-local generated artifact, written under
        ``scenario_root`` (the bundle root).
        """

        override_path = scenario_root / _IMAGE_OVERRIDE_RELATIVE_PATH
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
        scenario_root: Path | None = None,
    ) -> LabResult:
        """Start lab services using a generated realization override."""

        cmd = self._build_command(
            "up", profiles, compose_files=compose_files, scenario_root=scenario_root
        )
        build = build and not self._offline_staged
        if build:
            cmd.append("--build")
        if self._offline_staged:
            cmd.extend(["--pull", "never"])
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
        scenario_root: Path,
    ) -> LabResult:
        """Start services with the generated override when one exists.

        ``exclude_services`` (ADR-048 mixed realization) scales those Compose
        service names to zero: they were already realized directly by the
        generic materializer and must not also start as Compose containers.
        ``scenario_root`` is the bundle root Compose resolves against.
        """

        if compose_files is None:
            return self.start(
                profiles,
                build=build,
                exclude_services=exclude_services,
                scenario_root=scenario_root,
            )
        return self._start_with_compose_files(
            profiles,
            build=build,
            compose_files=compose_files,
            exclude_services=exclude_services,
            scenario_root=scenario_root,
        )
