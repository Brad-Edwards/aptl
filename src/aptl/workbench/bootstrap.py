"""Production assembly for the guest-side participant workbench."""

from __future__ import annotations

import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from starlette.requests import Request

from aptl.core.runstore import LocalRunStore
from aptl.core.session import ScenarioSession
from aptl.workbench.agent import ClaudeCodeManagedAgentAdapter
from aptl.workbench.app import (
    BrowserPrincipal,
    ParticipantAuthorizer,
    create_participant_workbench_app,
)
from aptl.workbench.browser_gateway import BrowserGateway, BrowserRoute
from aptl.workbench.credentials import EphemeralCredentialBroker
from aptl.workbench.guest_binding import GuestDispatchBinding
from aptl.workbench.profiles import ProfileId, WorkbenchConfigurationError
from aptl.workbench.runtime import GuestRuntimeBinding, WorkbenchPaths, WorkbenchRuntime


@dataclass(frozen=True)
class LocalWorkbenchSettings:
    """Trusted local project paths; appliance admission is a separate binding."""

    payload_root: Path
    state_dir: Path
    claude_executable: Path
    model: str
    node_executable: Path = Path("/usr/bin/node")


@dataclass(frozen=True)
class BrowserIngress:
    """Trusted localhost virtual hosts and upstream TLS verification policy."""

    routes: tuple[BrowserRoute, ...] = ()
    port: int = 8080
    tls_context: ssl.SSLContext | bool = True


# Compatibility name for callers; the settings do not require an appliance.
ApplianceWorkbenchSettings = LocalWorkbenchSettings


def create_appliance_workbench_app(
    settings: LocalWorkbenchSettings,
    *,
    secret_source: Mapping[str, str],
    authorizer: ParticipantAuthorizer,
    binding_path: Path | None = None,
    grant_id: str | None = None,
    aptl_executable: Path | None = None,
    browser: BrowserIngress = BrowserIngress(),
) -> BrowserGateway:
    """Wire the concrete agent, credential, session, run-store, and HTTP layers."""
    if binding_path is None or grant_id is None or aptl_executable is None:
        from aptl.workbench.profiles import WorkbenchConfigurationError

        raise WorkbenchConfigurationError(
            "workbench requires an enrolled canonical guest binding"
        )
    return create_local_workbench_app(
        settings,
        binding_path=binding_path,
        grant_id=grant_id,
        aptl_executable=aptl_executable,
        secret_source=secret_source,
        authorizer=authorizer,
        browser=browser,
    )


def render_guest_workbench_config(
    *,
    binding_path: Path,
    grant_id: str,
    profile: ProfileId,
    run_id: str,
    executable: Path,
    output: Path,
) -> Path:
    """Use the same admission relay for browser agents and authenticated host CLIs."""
    import json
    from datetime import UTC, datetime

    from aptl.utils.pathsafe import create_exclusive_nofollow
    from aptl.workbench.access import authorize_server
    from aptl.workbench.guest_binding import read_private_binding
    from aptl.workbench.profiles import WorkbenchConfigurationError, profile_for

    binding = read_private_binding(binding_path)
    grants = [grant for grant in binding.grants if grant.grant_id == grant_id]
    if (
        len(grants) != 1
        or grants[0].profile != profile.value
        or binding.run_id != run_id
    ):
        raise WorkbenchConfigurationError(
            "browser role does not match the enrolled grant"
        )
    grant = grants[0]
    record = binding.access.model_copy(update={"observed_at": datetime.now(UTC)})
    servers = {}
    for server in profile_for(profile).servers:
        authorize_server(record, grant, server.server_id)
        servers[server.server_id] = {
            "command": str(executable),
            "args": [
                "mcp-access",
                "dispatch",
                "--binding",
                str(binding_path),
                "--grant-id",
                grant_id,
                "--key-fingerprint",
                grant.public_key_fingerprint,
            ],
            "env": {
                "SSH_ORIGINAL_COMMAND": f"aptl-mcp-v1 {record.instance_id} {record.generation} {server.server_id}"
            },
        }
    relative = f"{output.name}/{profile.value}-{run_id}.json"
    create_exclusive_nofollow(
        output.parent, relative, (json.dumps({"mcpServers": servers}) + "\n").encode()
    )
    return output.parent / relative


class _BrowserProviderBroker(EphemeralCredentialBroker):
    """Browser agents receive only model auth; MCP service leases stay in relay."""

    def prepare(
        self, profile: ProfileId, run_id: str, aliases: tuple[str, ...]
    ) -> dict[str, str]:
        """Lease only provider authentication to the browser agent."""
        return self.prepare_named(profile, run_id, ("ANTHROPIC_API_KEY",))


def create_local_workbench_app(
    settings: LocalWorkbenchSettings,
    *,
    binding_path: Path,
    grant_id: str,
    aptl_executable: Path,
    secret_source: Mapping[str, str],
    authorizer: ParticipantAuthorizer,
    browser: BrowserIngress = BrowserIngress(),
) -> BrowserGateway:
    """Assemble against an existing full lab without appliance release metadata.

    An appliance uses the same factory with an appliance-bound dispatcher; the
    dispatcher then adds signed-launch and continuously refreshed boundary gates.
    """
    from aptl.workbench.dispatch import DispatchSelector
    from aptl.workbench.guest_binding import GuestAdmission, read_private_binding
    from aptl.workbench.profiles import WorkbenchConfigurationError, profile_for

    binding = read_private_binding(binding_path)
    if settings.payload_root.resolve() != binding.project_dir.resolve():
        raise WorkbenchConfigurationError("workbench and guest project differ")
    initial_grant = next(
        (grant for grant in binding.grants if grant.grant_id == grant_id), None
    )
    if initial_grant is None:
        raise WorkbenchConfigurationError("browser grant is missing")
    gate = GuestAdmission(
        binding_path,
        grant_id,
        initial_grant.public_key_fingerprint,
        DispatchSelector(
            binding.access.instance_id,
            binding.access.generation,
            profile_for(initial_grant.profile).servers[0].server_id,
        ),
    )

    def admit_run() -> str:
        """Revalidate the bound instance and run before agent execution."""
        current = read_private_binding(binding_path)
        if current.access != binding.access or current.run_id != binding.run_id:
            raise WorkbenchConfigurationError("workbench instance changed")
        gate.authorize()
        return current.run_id

    def authorized(request: Request) -> BrowserPrincipal | None:
        """Revalidate the browser identity and live guest grant."""
        principal = authorizer(request)
        current = read_private_binding(binding_path)
        grant = next(
            (grant for grant in current.grants if grant.grant_id == grant_id), None
        )
        from datetime import UTC, datetime

        if (
            not isinstance(principal, BrowserPrincipal)
            or grant is None
            or grant.revoked
            or grant.expires_at <= datetime.now(UTC)
            or principal.caller_id != grant_id
            or principal.profiles != (grant.profile,)
        ):
            return None
        try:
            gate.authorize()
        except (ValueError, OSError, RuntimeError):
            return None
        return principal

    state = settings.state_dir.resolve()
    runtime = WorkbenchRuntime(
        ScenarioSession(state),
        ClaudeCodeManagedAgentAdapter(
            claude_executable=settings.claude_executable,
            work_dir=state / "workbench" / "agent-work",
        ),
        LocalRunStore(state / "runs"),
        paths=WorkbenchPaths(
            payload_root=settings.payload_root,
            generated_config_dir=state / "workbench" / "mcp-config",
            node_executable=settings.node_executable,
        ),
        credential_broker=_BrowserProviderBroker(secret_source),
        model=settings.model,
        guest_binding=GuestRuntimeBinding(
            admit_run=admit_run,
            config_renderer=lambda profile, run_id: render_guest_workbench_config(
                binding_path=binding_path,
                grant_id=grant_id,
                profile=profile,
                run_id=run_id,
                executable=aptl_executable,
                output=state / "workbench" / "mcp-config",
            ),
        ),
    )
    return _attach_browser_surfaces(
        runtime, settings, binding_path, grant_id, binding, authorized, browser
    )


def _attach_browser_surfaces(
    runtime: WorkbenchRuntime,
    settings: LocalWorkbenchSettings,
    binding_path: Path,
    grant_id: str,
    binding: GuestDispatchBinding,
    authorized: ParticipantAuthorizer,
    browser: BrowserIngress,
) -> BrowserGateway:
    """Require the enrolled profile's local browser services and packaged guide."""
    state = settings.state_dir.resolve()
    from aptl.core.scenario_bundle import env_pack_bundle
    from aptl.workbench.browser_gateway import BrowserGateway
    from aptl.workbench.browser_mcp import attach_browser_mcp

    pack = env_pack_bundle(state / "workbench" / "packs")
    if pack.pack_identity != binding.access.scenario_pack:
        raise WorkbenchConfigurationError("workbench package identity changed")
    if not 0 < browser.port <= 65535:
        raise WorkbenchConfigurationError("invalid browser ingress port")
    selected = next(
        (grant for grant in binding.grants if grant.grant_id == grant_id), None
    )
    if selected is None:
        raise WorkbenchConfigurationError("browser grant is missing")
    from aptl.workbench.profiles import profile_for

    required = set(profile_for(selected.profile).bookmark_refs) - {
        "aptl-guide",
        "kali-desktop",
    }
    if not required <= {route.bookmark_ref for route in browser.routes}:
        raise WorkbenchConfigurationError("browser service routes are incomplete")
    urls = {
        route.bookmark_ref: f"http://{route.hostname}:{browser.port}/"  # NOSONAR - validated localhost traffic.
        for route in browser.routes
    }
    app = create_participant_workbench_app(runtime, authorized, bookmark_urls=urls)
    attach_browser_mcp(
        app,
        binding_path=binding_path,
        grant_id=grant_id,
        authorizer=authorized,
        guide=pack.read_asset("docs/attack-path.md").decode(),
    )
    return BrowserGateway(
        app,
        routes=browser.routes,
        authorizer=authorized,
        tls_context=browser.tls_context,
    )
