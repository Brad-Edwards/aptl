"""`icontract` wrappers for stable query/helper boundaries on the SDL.

ADR-014 §"Contract Guards" admits `icontract` as a fail-fast guard over
already-validated SDL state, *not* as a third schema layer. Two
production-readiness properties are baked into the wrappers below so a
contract added to an SDL accessor never quietly drops in production and
never leaks the bound `Scenario`'s `repr()` past the breach point:

1. `icontract.require`/`icontract.ensure` default `enabled=__debug__`, so
   under an optimized interpreter (`python -O`) the decorator becomes a
   no-op and the precondition is silently dropped. `enabled=True` pins
   the guard on unconditionally — the same fix `_runtime_require` in
   `aptl.core.lab` applied to the lab-orchestration surface.
2. `icontract`'s default `ViolationError` renderer interpolates `repr()`
   of every bound condition argument. The bound argument to an SDL
   accessor is `Scenario`, a 21-section model whose nested fields carry
   author free-text and may someday carry credential-shaped values
   under `${var}` substitutions. A direct caller logging an exception
   (or a future test capturing it) would surface that repr in plain
   text. We force a fixed-template message via the `error=` callback so
   the contract is secret-safe at the source, not just at consumers.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import icontract


def _narrow_error_factory(
    description: str,
) -> Callable[[], icontract.ViolationError]:
    """Return a zero-arg `error=` factory `icontract` will call directly.

    `icontract` introspects the callable's signature and tries to resolve
    every named parameter against the condition's bound kwargs. A no-arg
    factory sidesteps that path: `icontract` detects `parameters` is
    empty, skips kwarg resolution, and calls `factory()` directly.
    """

    def _factory() -> icontract.ViolationError:
        """Build the fixed-message `ViolationError` for this contract."""
        return icontract.ViolationError(description)

    return _factory


def sdl_require(
    condition: Callable[..., bool], description: str
) -> Callable[[Any], Any]:
    """`icontract.require` for SDL query/helper boundaries.

    The wrapper forces `enabled=True` (survives `python -O`) and pins the
    violation message to ``description`` so a `Scenario` repr never
    crosses the contract boundary into logs, tests, or user-facing
    surfaces. Returns a decorator suitable for attaching to instance
    methods on Pydantic-derived SDL models.
    """
    return icontract.require(
        condition,
        description=description,
        enabled=True,
        error=_narrow_error_factory(description),
    )


def sdl_ensure(
    condition: Callable[..., bool], description: str
) -> Callable[[Any], Any]:
    """`icontract.ensure` for SDL query/helper boundaries.

    Same secret-safety + ``python -O`` properties as `sdl_require`.
    Use for postconditions that assert the returned object belongs to
    the same scenario (identity, not equality). Returns a decorator
    suitable for attaching to instance methods on Pydantic-derived SDL
    models.
    """
    return icontract.ensure(
        condition,
        description=description,
        enabled=True,
        error=_narrow_error_factory(description),
    )
