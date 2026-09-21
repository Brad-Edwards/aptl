"""Docker Compose capability parsing on supported guest distributions."""

import pytest

from aptl.core.deployment._compose_stateful_graph import compose_version


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("2.40.3+ds1-0ubuntu1", (2, 40, 3)),
        ("Docker Compose version v2.24.4", (2, 24, 4)),
        ("v2.24.3-rc1+build", (2, 24, 3)),
        ("not a version", None),
    ],
)
def test_compose_version_accepts_distribution_build_suffix(
    output: str, expected: tuple[int, int, int] | None
) -> None:
    assert compose_version(output) == expected
