"""Backend implementation choices for Shuffle application components."""

from __future__ import annotations

from aptl.backends._raes_backend_implementation_types import (
    BackendImplementationProfile,
    SemanticRuntimeSelector,
    environment as _environment,
    published_port as _port,
    variable as _variable,
)

SHUFFLE_APPLICATION_PROFILES = (
    BackendImplementationProfile(
        profile_id="shuffle-backend",
        selector=SemanticRuntimeSelector(
            "platform_applications", "product", "Shuffle", "unversioned"
        ),
        source_name="ghcr.io/shuffle/shuffle-backend",
        source_version="unversioned",
        image_ref=(
            "ghcr.io/shuffle/shuffle-backend@sha256:"
            "d4a5d2bf1f956955b68b099ba1c38997e4b257b2518215e0427f433515bea5c8"
        ),
        runtime_selections={
            "runtime-environment": _environment(
                _variable("SHUFFLE_OPENSEARCH_URL", "https://shuffle-opensearch:9200"),
                _variable("SHUFFLE_OPENSEARCH_USERNAME", "admin"),
                _variable(
                    "SHUFFLE_OPENSEARCH_PASSWORD",
                    "StrongPassword123!",
                    classification="secret_fixture",
                ),
                _variable("SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY", "true"),
                _variable("SHUFFLE_DEFAULT_USERNAME", "admin"),
                _variable(
                    "SHUFFLE_DEFAULT_PASSWORD",
                    "ShuffleAdmin2024!",
                    classification="secret_fixture",
                ),
                _variable(
                    "SHUFFLE_DEFAULT_APIKEY",
                    "31a211c4-ea5c-4a49-b022-5e2434e758a7",
                    classification="secret_fixture",
                ),
                _variable("SHUFFLE_APP_SDK_TIMEOUT", "120"),
            )
        },
    ),
    BackendImplementationProfile(
        profile_id="shuffle-frontend",
        selector=SemanticRuntimeSelector(
            "software_components", "component_id", "shuffle-frontend", "unversioned"
        ),
        source_name="ghcr.io/shuffle/shuffle-frontend",
        source_version="unversioned",
        image_ref=(
            "ghcr.io/shuffle/shuffle-frontend@sha256:"
            "4d700a6f0822cb081822bd2fa6c633080553bdd4313aed2c4bdce75b87e82836"
        ),
        runtime_selections={
            "runtime-environment": _environment(
                _variable("BACKEND_HOSTNAME", "shuffle-backend")
            ),
            "published-ports": [_port(443, 3443), _port(80, 3001)],
        },
    ),
    BackendImplementationProfile(
        profile_id="shuffle-orborus",
        selector=SemanticRuntimeSelector(
            "software_components", "component_id", "shuffle-orborus", "unversioned"
        ),
        source_name="ghcr.io/shuffle/shuffle-orborus",
        source_version="unversioned",
        image_ref=(
            "ghcr.io/shuffle/shuffle-orborus@sha256:"
            "94e61e7916aea28351fce3851f26f14fb85204f1567a8807d137321418366dba"
        ),
        runtime_selections={
            "runtime-environment": _environment(
                _variable("BASE_URL", "http://shuffle-backend:5001"),
                _variable("CLEANUP", "false"),
                _variable("DOCKER_API_VERSION", "1.44"),
                _variable("ENVIRONMENT_NAME", "Shuffle"),
                _variable("SHUFFLE_APP_SDK_TIMEOUT", "300"),
                _variable("SHUFFLE_AUTO_IMAGE_DOWNLOAD", "false"),
                _variable("SHUFFLE_BASE_IMAGE_NAME", "frikky/shuffle"),
                _variable("SHUFFLE_ORBORUS_EXECUTION_TIMEOUT", "600"),
                _variable(
                    "SHUFFLE_WORKER_IMAGE",
                    "ghcr.io/shuffle/shuffle-worker@sha256:"
                    "fd0d420a5e0cd41f3979335e51912e8dd423e7ce540d1dfa24efdc98fb6071bd",
                ),
            )
        },
    ),
)
