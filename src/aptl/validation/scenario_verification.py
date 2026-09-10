"""The seam scenario verification plugins are discovered and run through (#878).

Semantic verification — "did the SOC actually detect the attack" — is about one
scenario *and* one backend at once, so it belongs in neither the portable
scenario contract nor a backend that must serve any scenario. It is the plugin
quadrant (Shifter #1293), and this module is APTL's side of it.

What core owns, and keeps: discovery, compatibility matching, prerequisite
sequencing, deadlines, the report shape, redaction, and turning any failure of
the machinery into a stable ``blocked`` outcome. What a plugin owns: which node
is the attacker, what the defensive stack is, and what evidence proves detection
traversed it.

**This framework holds no scenario knowledge.** Not a fallback, not an example,
not a test-only branch. Every scenario-specific fact lives in its own top-level
adapter package — ``aptl_techvault`` is the first — reached only through
installed entry-point metadata, and a conformance test asserts that no entry
point resolves into ``aptl.`` itself. Adding a second scenario adds a package;
it never edits this file. If it did, the seam would be decorative.

Those adapter packages ship in this distribution and release with it, because
an adapter is specific to one scenario *and* one backend, and only the backend
can write it: a scenario author cannot write an adapter for a backend they have
never seen, and many backends are private. Owning them here is also what lets a
single install give an operator every extension surface a scenario needs. The
boundary that matters is the code boundary above, not a packaging boundary.

Discovery is fail-closed on purpose. No match, several matches, a version
mismatch, or a plugin that fails to load all produce ``blocked``: no complete
semantic verdict was possible. That is terminal and non-successful, and must
never be reported as passed, skipped, or degraded — a range whose verification
could not run has not been verified.

Loading an entry point executes installed Python with this process's authority.
Entry points are a discovery mechanism, not a sandbox, so nothing here
downloads, auto-installs, scans a range directory, or accepts a module path from
scenario data or configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Protocol

from aptl.backends.identity import BackendIdentity

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

#: The single entry-point group a scenario verifier registers under. Entries
#: resolve into per-scenario adapter packages, never into ``aptl.`` itself; see
#: ``pyproject.toml`` and the conformance test.
ENTRY_POINT_GROUP = "aptl.scenario_verifiers"

#: The extension contract version. A plugin declares the version it was built
#: against and is refused when it does not match, rather than being run against a
#: context whose meaning has changed underneath it.
#:
#: ``2`` replaced the parallel per-dimension compatibility lists with atomic
#: :class:`QualifiedTarget` pairs (#879), so a plugin built against ``1`` must be
#: refused rather than reinterpreted.
EXTENSION_API_VERSION = "2"

#: Version of the normalized report emitted by core.  This is independent of
#: the extension API: the former is persisted/projection data, while the latter
#: is the callable contract an installed verifier implements.
REPORT_API_VERSION = "1"


class VerificationStatus(str, Enum):
    """The authoritative outcome of a verification run.

    Three states, deliberately distinct. Collapsing ``BLOCKED`` into either of
    the others is the failure mode this enum exists to prevent: a run that could
    not happen is not a pass, and it is not evidence of a defect either.
    """

    PASSED = "passed"
    FAILED = "failed"
    BLOCKED = "blocked"


class PrerequisiteStatus(str, Enum):
    """Whether one precondition for semantic verification held."""

    SATISFIED = "satisfied"
    UNSATISFIED = "unsatisfied"


@dataclass(frozen=True)
class PrerequisiteResult(object):
    """One typed precondition outcome.

    Prerequisites are data, never executable policy: a stable id, a status, and
    a bounded diagnostic. They are not shell commands, import locators, or paths,
    so a plugin cannot use them to widen what it is allowed to do.
    """

    prerequisite_id: str
    status: PrerequisiteStatus
    diagnostic: str = ""

    @property
    def satisfied(self) -> bool:
        """Return whether this precondition held."""
        return self.status is PrerequisiteStatus.SATISFIED


@dataclass(frozen=True)
class VerificationCheck(object):
    """One semantic assertion the plugin evaluated."""

    check_id: str
    status: VerificationStatus
    diagnostic: str = ""
    category: str = "semantic_verification"

    @property
    def name(self) -> str:
        """Return the historical live-gate name for compatibility callers."""

        return self.check_id

    @property
    def diagnostics(self) -> tuple[str, ...]:
        """Return the diagnostic through the historical tuple projection."""

        return (self.diagnostic,) if self.diagnostic else ()

    @property
    def passed(self) -> bool:
        """Return whether this check reached the sole successful outcome."""

        return self.status is VerificationStatus.PASSED


@dataclass(frozen=True)
class ScenarioIdentity(object):
    """Which scenario is being verified, bound to its admitted content.

    The digest is what makes matching honest: a plugin is written against
    specific scenario content, and a filename or display name would let it run
    against something that merely shares a label.
    """

    identity: str
    content_digest: str
    source_kind: str = ""
    version: str = ""


@dataclass(frozen=True)
class QualifiedTarget(object):
    """One scenario-and-backend combination a plugin release has qualified.

    Qualification is atomic, and that is the whole point of the type. Declaring
    admitted versions and admitted content digests as separate lists silently
    admits their cross product: a plugin that qualified release 0.1.0 at one
    digest and release 0.2.0 at another has said nothing about 0.1.0 at the
    second digest, yet parallel lists would run against it (#879).

    A pair is a claim that *this* content on *this* backend was qualified
    together. Naming several pairs is allowed; each one is its own claim and
    needs its own evidence.
    """

    scenario: ScenarioIdentity
    backend: BackendIdentity


@dataclass(frozen=True)
class VerificationContext(object):
    """Everything a plugin is given, and nothing more.

    Deliberately narrow. It carries no run store, no destination paths, no raw
    ``AptlConfig``, no ``EnvVars`` or ``.env`` mapping, no process environment,
    no general subprocess client, and no unrestricted backend handle. The
    framework owns credentials and persistence; a plugin that needed any of those
    would be taking on responsibilities the seam exists to keep in core.

    ``operations`` is the capability surface the plugin actually works through.
    It is scenario-neutral by construction: adding a second scenario must not
    require a method here named after any particular product, protocol, or
    detection technology. If one is ever needed, the surface is wrong.
    """

    run_id: str
    attempt_id: str
    scenario: ScenarioIdentity
    backend: BackendIdentity
    extension_api_version: str = EXTENSION_API_VERSION
    #: Absolute deadline on the host monotonic clock.  Wall time is evidence,
    #: never timeout authority.
    deadline_monotonic: float = float("inf")
    poll_interval_seconds: float = 10.0
    operations: object | None = None
    #: Narrow, already-redacted facts the framework observed while booting, for
    #: a plugin to read rather than rediscover. Never credentials.
    observations: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class VerificationReport(object):
    """The one report shape, replacing the live gate's own.

    ``status`` is the single authoritative outcome. The derived ``passed``
    property exists only for compatibility with older gate callers; it is not a
    serialized field and therefore cannot contradict ``status``.
    """

    status: VerificationStatus
    scenario: ScenarioIdentity
    backend: BackendIdentity
    api_version: str = REPORT_API_VERSION
    run_id: str = ""
    attempt_id: str = ""
    plugin_id: str = ""
    distribution: str = ""
    distribution_version: str = ""
    entry_point: str = ""
    extension_api_version: str = EXTENSION_API_VERSION
    prerequisites: tuple[PrerequisiteResult, ...] = ()
    checks: tuple[VerificationCheck, ...] = ()
    diagnostics: tuple[str, ...] = ()
    elapsed_seconds: float = 0.0

    @property
    def passed(self) -> bool:
        """Return whether this report reached the sole successful outcome."""

        return self.status is VerificationStatus.PASSED

    def failures(self) -> tuple[VerificationCheck, ...]:
        """Return checks that either failed or could not run."""

        return tuple(
            check
            for check in self.checks
            if check.status is not VerificationStatus.PASSED
        )

    def failure_categories(self) -> tuple[str, ...]:
        """Return distinct categories in their first-failing-check order."""

        categories: list[str] = []
        for check in self.failures():
            category = check.category
            if category and category not in categories:
                categories.append(category)
        return tuple(categories)

    def _headline(self) -> str:
        """Return the one-line verdict, naming the release that produced it.

        The distribution and version sit alongside the plugin id because an
        operator reading a verdict needs to know which installed release
        reached it, and the id alone does not say that.
        """

        origin = (
            f"{self.distribution}=={self.distribution_version}"
            if self.distribution
            else "(none)"
        )
        return (
            f"scenario verification — scenario={self.scenario.identity} "
            f"backend={self.backend.target_name} "
            f"plugin={self.plugin_id or '(none)'} from {origin}: "
            f"{self.status.value.upper()}"
        )

    def _rendered_prerequisites(self) -> list[str]:
        """Return the prerequisite lines, each with its bounded diagnostic."""

        lines: list[str] = []
        for prerequisite in self.prerequisites:
            marker = "ok" if prerequisite.satisfied else "UNMET"
            lines.append(f"  [{marker}] prerequisite {prerequisite.prerequisite_id}")
            if prerequisite.diagnostic:
                lines.append(f"        - {prerequisite.diagnostic}")
        return lines

    def _rendered_checks(self) -> list[str]:
        """Return the semantic-check lines, each with its diagnostics."""

        lines: list[str] = []
        for check in self.checks:
            suffix = f" ({check.category})" if check.category else ""
            lines.append(f"  [{check.status.value}] {check.check_id}{suffix}")
            lines.extend(f"        - {item}" for item in check.diagnostics)
        return lines

    def render(self) -> str:
        """Render a bounded, human-readable summary."""

        lines = [self._headline()]
        lines.extend(self._rendered_prerequisites())
        lines.extend(self._rendered_checks())
        lines.extend(f"  - {diagnostic}" for diagnostic in self.diagnostics)
        categories = self.failure_categories()
        if categories:
            lines.append("  failing layers: " + ", ".join(categories))
        return "\n".join(lines)


class ScenarioVerifier(Protocol):
    """What an installed plugin must provide.

    One operation. The plugin declares which scenario and backend it is written
    for and is refused when the running range is not that; it never inspects the
    process to decide for itself whether it applies.
    """

    #: Stable identifier for this verifier, reported in evidence.
    plugin_id: str
    #: Extension contract version this plugin was built against.
    extension_api_version: str
    #: Every scenario-and-backend combination this release qualified, each one
    #: exact and atomic. An empty declaration is not a wildcard: it qualifies
    #: nothing, so every run against it is blocked.
    qualified_targets: Sequence[QualifiedTarget]

    def run(self, context: VerificationContext) -> VerificationReport:
        """Evaluate the scenario's semantic expectations against a live range."""
        ...


__all__ = [
    "ENTRY_POINT_GROUP",
    "EXTENSION_API_VERSION",
    "REPORT_API_VERSION",
    "BackendIdentity",
    "PrerequisiteResult",
    "PrerequisiteStatus",
    "QualifiedTarget",
    "ScenarioIdentity",
    "ScenarioVerifier",
    "VerificationCheck",
    "VerificationContext",
    "VerificationReport",
    "VerificationStatus",
]
