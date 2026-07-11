"""Docker Compose content-placement realization (issue #689)."""

from __future__ import annotations

from collections.abc import Sequence

from aptl.core.content_seed import build_content_volume_seeds
from aptl.core.deployment.realization import DeploymentContentRealization

# Reuses the Suricata seeder image: it is already pulled unconditionally by
# every lab start (Suricata is part of the default profile set), so content
# realization introduces no new image dependency (ADR-043 "already in the
# lab's supply chain"). The image only needs `/bin/sh`, `mkdir`, and `cp`,
# which this Alpine-based image provides.
CONTENT_SEEDER_IMAGE = "jasonish/suricata:7.0"


class ComposeRealizationContentMixin:
    """Realize typed scenario content placements through Docker Compose."""

    def realize_content(
        self,
        content: Sequence[DeploymentContentRealization],
        *,
        seeder_image: str,
    ) -> None:
        """Materialize typed content placements via the ADR-043 seed seam."""

        if not content:
            return
        seeds = build_content_volume_seeds(self._project_dir, content)
        self.seed_named_volumes(seeds, seeder_image=seeder_image)
