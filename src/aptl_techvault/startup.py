"""TechVault startup enrichment for the APTL deployment backend."""

from __future__ import annotations

from aptl.backends.scenario_startup import (
    EXTENSION_API_VERSION,
    ContainerEnvironmentBinding,
    EnvironmentAlias,
    McpServerCredentials,
    ScenarioStartupPlan,
    StartupCapability,
    StartupHook,
    StartupHookContext,
)
from aptl.backends.scenario_startup_policy import (
    ScenarioComposeStartupPolicy,
    StartupHealthDependency,
    StartupHealthProbe,
)
from aptl.backends.scenario_service_policy import (
    ScenarioComposeServicePolicy,
    ServiceEnvironmentFile,
    ServiceFileMount,
    ServiceContainerNameEnvironment,
)
from raes_processor.semantics.realization import CONCERN_PAYLOAD_PATH
from aptl.core.scenario_bundle import ScenarioBundle
from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact
from aptl_techvault.log_sources import realize_log_sources
from aptl_techvault.database import realize_database
from aptl_techvault.redis_acl_observation import observe_redis_app_authorizations
from aptl_techvault.runtime_parameters import TECHVAULT_PACK_SET_DIGEST
from aptl_techvault.wazuh_credentials import techvault_wazuh_environment

log = get_logger("techvault-startup")
_API_LOG_PATH = "/var/ossec/logs/api.log"
_API_LOG_TAIL_BYTES = 4096


def _bounded_count(value: object) -> int | None:
    """Accept only small nonnegative decimal counts from diagnostic sources."""

    if isinstance(value, int) and not isinstance(value, bool):
        return value if 0 <= value <= 1_000_000_000_000 else None
    if isinstance(value, str) and value.isascii() and value.isdecimal():
        return int(value) if len(value) <= 12 else None
    return None


def _diagnostic_text(
    context: StartupHookContext, container: str, argv: list[str], limit: int
) -> str | None:
    """Read a fixed in-container diagnostic without retaining stderr or raw logs."""

    try:
        result = context.backend.container_exec(container, argv, timeout=3)
    except Exception:
        return None
    if result.returncode != 0 or not isinstance(result.stdout, str):
        return None
    return result.stdout[:limit]


def _api_log_phase(tail: str) -> str:
    """Classify the latest known startup marker without returning log text."""

    markers = (
        ("tls_generation", "Generated certificate file in WAZUH_PATH/"),
        ("rbac_check", "Checking RBAC database integrity"),
        ("rbac_complete", "RBAC database integrity check finished successfully"),
        ("listening", "Listening on"),
    )
    latest = max(
        ((tail.rfind(marker), phase) for phase, marker in markers),
        default=(-1, "unknown"),
    )
    return latest[1] if latest[0] >= 0 else "unknown"


def _api_exception_class(tail: str) -> str | None:
    """Extract only known exception names, never a free-form error message."""

    known = {
        "FileNotFoundError",
        "MemoryError",
        "OSError",
        "PermissionError",
        "RuntimeError",
        "SystemExit",
        "TimeoutError",
        "ValueError",
    }
    for line in reversed(tail.splitlines()):
        name = line.partition(":")[0].strip()
        if name in known:
            return name
    return None


def _oom_counters(events: str | None) -> dict[str, int]:
    """Parse only the two OOM counters from a bounded cgroup read."""

    counters: dict[str, int] = {}
    for line in (events or "").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] in {"oom", "oom_kill"}:
            count = _bounded_count(fields[1])
            if count is not None:
                counters[fields[0]] = count
    return counters


def _container_evidence(info: dict[str, object]) -> dict[str, object]:
    """Select scalar Docker facts without logging inspect output."""

    state = info.get("State")
    state = state if isinstance(state, dict) else {}
    oom = state.get("OOMKilled")
    return {
        "container_running": state.get("Status") == "running",
        "container_oom": oom if isinstance(oom, bool) else None,
        "restart_count": _bounded_count(info.get("RestartCount")),
    }


def _api_log_evidence(tail: str | None, log_bytes: int | None) -> dict[str, object]:
    """Reduce the raw tail to allowlisted facts before it reaches logging."""

    if tail is None:
        return {
            "api_log_bytes": log_bytes,
            "api_log_offset": None,
            "api_phase": "unknown",
            "warnings": None,
            "errors": None,
            "tracebacks": None,
            "critical": None,
            "exception_class": None,
            "unclassified_fatal": None,
        }
    errors = tail.count("ERROR:")
    critical = tail.count("CRITICAL:")
    tracebacks = tail.count("Traceback")
    return {
        "api_log_bytes": log_bytes,
        "api_log_offset": (
            max(0, log_bytes - _API_LOG_TAIL_BYTES)
            if log_bytes is not None
            else None
        ),
        "api_phase": _api_log_phase(tail),
        "warnings": tail.count("WARNING:"),
        "errors": errors,
        "tracebacks": tracebacks,
        "critical": critical,
        "exception_class": _api_exception_class(tail),
        "unclassified_fatal": bool(errors or critical or tracebacks),
    }


def _log_missing_api_evidence(
    context: StartupHookContext, container: str, info: dict[str, object]
) -> None:
    """Emit one allowlisted snapshot before an in-place API repair changes it."""

    size_text = _diagnostic_text(
        context, container, ["stat", "-c", "%s", _API_LOG_PATH], 32
    )
    tail = _diagnostic_text(
        context,
        container,
        ["tail", "-c", str(_API_LOG_TAIL_BYTES), _API_LOG_PATH],
        _API_LOG_TAIL_BYTES,
    )
    events = _diagnostic_text(
        context,
        container,
        ["head", "-c", "512", "/sys/fs/cgroup/memory.events"],
        512,
    )
    log_bytes = _bounded_count(size_text.strip()) if size_text is not None else None
    counters = _oom_counters(events)
    facts = {
        "status": "partial",
        "status_exit": 1,
        "api": "absent",
        "other_daemons": True,
        "cgroup_oom": counters.get("oom"),
        "cgroup_oom_kill": counters.get("oom_kill"),
        **_container_evidence(info),
        **_api_log_evidence(tail, log_bytes),
    }
    log.warning("Wazuh manager API absent before recovery: %s", redact(facts))


class TechVaultStartupProvider:
    """Describe the optional TechVault seed through the generic adapter seam."""

    extension_api_version = EXTENSION_API_VERSION
    supported_pack_id = "techvault"
    supported_pack_versions = ("0.1.1",)
    supported_pack_set_digests = (TECHVAULT_PACK_SET_DIGEST,)

    @staticmethod
    def prepare_stack_environment(context: StartupHookContext) -> object:
        """Execute TechVault's selected preparation phase in core order."""

        return context.run_operation()

    @staticmethod
    def resolve(bundle: ScenarioBundle) -> ScenarioStartupPlan:
        return ScenarioStartupPlan(
            seed_script="scripts/seed-prime.sh",
            required_profiles=(
                "wazuh",
                "enterprise",
                "victim",
                "kali",
                "fileshare",
                "soc",
            ),
            activation_profiles=("soc",),
            environment_aliases=(
                EnvironmentAlias(target="ADMIN_KEY", source="MISP_API_KEY"),
            ),
            environment_fixtures=techvault_wazuh_environment(bundle),
            container_environment=(
                ContainerEnvironmentBinding("CORTEX_CONTAINER", "aptl-cortex"),
                ContainerEnvironmentBinding("THEHIVE_CONTAINER", "aptl-thehive"),
                ContainerEnvironmentBinding("MISP_CONTAINER", "aptl-misp"),
                ContainerEnvironmentBinding(
                    "SHUFFLE_CONTAINER", "aptl-shuffle-frontend"
                ),
                ContainerEnvironmentBinding("KALI_CONTAINER", "aptl-kali"),
                ContainerEnvironmentBinding(
                    "WAZUH_MANAGER_CONTAINER", "aptl-wazuh-manager"
                ),
            ),
            lifecycle_capabilities=frozenset(
                {
                    StartupCapability.SSH,
                    StartupCapability.HOST_TOOLS,
                    StartupCapability.MCP,
                    StartupCapability.NATIVE_EVIDENCE,
                }
            ),
            startup_hooks=frozenset(
                {
                    StartupHook.STACK_ENVIRONMENT,
                    StartupHook.BEFORE_BACKEND_RETRY,
                }
            ),
            seed_environment_keys=(
                "APTL_HP_WAZUH_INDEXER_9200",
                "APTL_SHUFFLE_WEBHOOK_FILE",
                "INDEXER_URL",
                "INDEXER_USERNAME",
                "INDEXER_PASSWORD",
                "MISP_API_KEY",
                "MISP_URL",
                "SHUFFLE_API_KEY",
                "SHUFFLE_URL",
                "CORTEX_API_KEY",
                "THEHIVE_API_KEY",
            ),
            mcp_build_script="mcp/build-all-mcps.sh",
            mcp_server_keys=(
                McpServerCredentials("aptl-casemgmt", ("THEHIVE_API_KEY",)),
                McpServerCredentials(
                    "aptl-indexer",
                    (
                        "INDEXER_USERNAME",
                        "INDEXER_PASSWORD",
                        "API_USERNAME",
                        "API_PASSWORD",
                    ),
                ),
                McpServerCredentials(
                    "aptl-network", ("INDEXER_USERNAME", "INDEXER_PASSWORD")
                ),
                McpServerCredentials("aptl-threatintel", ("MISP_API_KEY",)),
                McpServerCredentials("aptl-soar", ("SHUFFLE_API_KEY",)),
                McpServerCredentials(
                    "aptl-wazuh",
                    (
                        "INDEXER_USERNAME",
                        "INDEXER_PASSWORD",
                        "API_USERNAME",
                        "API_PASSWORD",
                    ),
                ),
            ),
            native_mcp_ingress=True,
        )

    @staticmethod
    def before_backend_retry(context: StartupHookContext) -> None:
        """Repair a stopped manager API before core's single admitted retry."""

        container = "aptl-wazuh-manager"
        probe = [
            "sh",
            "-c",
            "ls /proc/[0-9]*/comm 2>/dev/null | while read f; do "
            'read n < "$f"; case "$n" in wazuh-*) echo "$n";; esac; '
            "done | sort -u | wc -l",
        ]
        try:
            info = context.backend.container_inspect(container)
            if (info.get("State") or {}).get("Status") != "running":
                return
            result = context.backend.container_exec(container, probe, timeout=10)
            observed = (result.stdout or "").strip() if result.returncode == 0 else ""
            count = int(observed) if observed else None
            if count == 0:
                context.backend.container_restart(container)
            elif count is not None and count > 0:
                TechVaultStartupProvider._start_missing_wazuh_api(
                    context, container, info
                )
        except Exception as exc:
            log.warning(
                "Wazuh manager retry preparation failed (%s); "
                "readiness remains authoritative",
                type(exc).__name__,
            )

    @staticmethod
    def _start_missing_wazuh_api(
        context: StartupHookContext, container: str, info: dict[str, object]
    ) -> None:
        """Start only an API that Wazuh reports absent in a live manager."""

        status = context.backend.container_exec(
            container,
            ["/var/ossec/bin/wazuh-control", "status"],
            timeout=10,
        )
        # Exit 1 is Wazuh's completed observation of a stopped daemon.
        if status.returncode != 1:
            return
        api_lines = [
            line
            for line in (status.stdout or "").splitlines()
            if "wazuh-apid" in line
        ]
        if api_lines != ["wazuh-apid not running..."]:
            return

        try:
            _log_missing_api_evidence(context, container, info)
        except Exception as exc:
            log.warning(
                "Wazuh manager API evidence unavailable (%s)", type(exc).__name__
            )

        repair = context.backend.container_exec(
            container,
            ["/var/ossec/bin/wazuh-control", "start"],
            timeout=30,
        )
        if repair.returncode != 0:
            log.warning(
                "Wazuh manager API recovery failed (exit %s); "
                "readiness remains authoritative",
                repair.returncode,
            )
            return
        log.info("Wazuh manager API recovery invoked; readiness remains authoritative")

    @staticmethod
    def compose_startup_policy() -> ScenarioComposeStartupPolicy:
        """Wait for TechVault's stateful backends before dependent JVM services.

        The pack declares these dependency edges, but its generated Compose
        base otherwise starts dependents as soon as their containers exist.
        Cassandra can still be initializing then, causing TheHive to exit on
        the first user-visible boot. These probes strengthen only those edges.
        """

        return ScenarioComposeStartupPolicy(
            probes=(
                StartupHealthProbe(
                    "thehive-cassandra",
                    ("CMD", "cqlsh", "-e", "describe cluster"),
                ),
                StartupHealthProbe(
                    "thehive-es",
                    ("CMD", "curl", "-fsS", "http://localhost:9200/_cluster/health"),
                ),
                StartupHealthProbe(
                    "cortex",
                    ("CMD", "curl", "-fsS", "http://localhost:9001/api/status"),
                    start_period_seconds=180,
                ),
            ),
            dependencies=(
                StartupHealthDependency("cortex", "thehive-es"),
                StartupHealthDependency("thehive", "thehive-cassandra"),
                StartupHealthDependency("thehive", "thehive-es"),
                StartupHealthDependency("thehive", "cortex"),
            ),
        )

    @staticmethod
    def compose_service_policy() -> ScenarioComposeServicePolicy:
        """Connect SDL-owned certificate files to upstream image TLS paths.

        The pack delivers these generated files at portable locations. The
        image-specific paths and TheHive Play config belong to this adapter.
        """

        return ScenarioComposeServicePolicy(
            mounts=(
                ServiceFileMount(
                    "shuffle-frontend",
                    "config/soc_certs/shuffle-frontend/server.pem",
                    "/etc/nginx/fullchain.cert.pem",
                ),
                ServiceFileMount(
                    "shuffle-frontend",
                    "config/soc_certs/shuffle-frontend/server.key",
                    "/etc/nginx/privkey.pem",
                ),
                ServiceFileMount(
                    "thehive",
                    "config/soc_certs/thehive/keystore.p12",
                    "/etc/thehive/keystore.p12",
                ),
                ServiceFileMount(
                    "thehive",
                    "config/thehive/application.conf",
                    "/etc/thehive/application.conf",
                ),
            ),
            environment_files=(
                ServiceEnvironmentFile(
                    "thehive", "config/soc_certs/thehive/keystore.p12.password"
                ),
            ),
            container_name_environment=(
                ServiceContainerNameEnvironment(
                    "shuffle-orborus", "ORBORUS_CONTAINER_NAME", "shuffle-orborus"
                ),
            ),
        )

    @staticmethod
    def realize_runtime(backend: object, nodes: tuple[object, ...]) -> list[str]:
        """Realize pack-declared native producers and the customer database."""

        failures = realize_log_sources(backend, nodes)
        if failures:
            return failures
        return realize_database(backend, nodes)

    @staticmethod
    def observe_runtime(backend: object, node: object) -> dict[tuple[str, ...], object]:
        """Corroborate TechVault's generated cache ACL without exposing it."""

        runtime = getattr(node, "runtime", None)
        container = getattr(node, "container_name", "")
        if (
            getattr(node, "name", "") != "misp-redis"
            or runtime is None
            or not container
        ):
            return {}
        observed = observe_redis_app_authorizations(backend, container, runtime)
        if observed is None:
            return {}
        return {CONCERN_PAYLOAD_PATH["runtime-app-authorizations"]: observed}


provider = TechVaultStartupProvider()

__all__ = ["TechVaultStartupProvider", "provider"]
