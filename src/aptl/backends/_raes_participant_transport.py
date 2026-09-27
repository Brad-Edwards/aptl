"""Host transport and role-scoped MCP configuration for participant delivery."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
from pathlib import Path

from aptl.backends._raes_participant_models import ParticipantTurnResult
from aptl.utils.pathsafe import create_exclusive_nofollow
from aptl.workbench.agent import (
    _admitted_executable,
    _parse_agent_result,
    _read_private_config,
)
from aptl.workbench.process import (
    AgentExecutionError,
    BoundedProcessRunner,
    ProcessRunner,
)
from aptl.workbench.profiles import ProfileId, profile_for

_PROVIDER_AUTH_ENVIRONMENT = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "CLAUDE_CODE_USE_VERTEX",
        "ANTHROPIC_VERTEX_PROJECT_ID",
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "CLOUDSDK_CONFIG",
        "SHIFTER_GOOGLE_APPLICATION_CREDENTIALS",
        "CLAUDE_CODE_USE_BEDROCK",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
    }
)

_MCP_COMMON_RUNTIME_ENVIRONMENT = frozenset({"APTL_MCP_DISABLE_DOTENV"})

_MCP_RUNTIME_ENVIRONMENT = {
    "aptl-red": frozenset(
        {
            "APTL_HP_KALI_SSH_PROXY_2023",
            "APTL_MCP_ADMITTED_RUN_ID",
            "APTL_MCP_KALI_HOST",
            "APTL_MCP_RUN_STORE_BASE",
            "APTL_STATE_DIR",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
        }
    ),
    "aptl-casemgmt": frozenset(
        {
            "APTL_HP_THEHIVE_9000",
            "APTL_MCP_ADMITTED_RUN_ID",
            "APTL_MCP_RUN_STORE_BASE",
            "APTL_STATE_DIR",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
        }
    ),
    "aptl-indexer": frozenset(
        {
            "APTL_HP_WAZUH_INDEXER_9200",
            "APTL_HP_WAZUH_MANAGER_55000",
            "APTL_MCP_ADMITTED_RUN_ID",
            "APTL_MCP_RUN_STORE_BASE",
            "APTL_STATE_DIR",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
        }
    ),
    "aptl-network": frozenset(
        {
            "APTL_HP_WAZUH_INDEXER_9200",
            "APTL_MCP_ADMITTED_RUN_ID",
            "APTL_MCP_RUN_STORE_BASE",
            "APTL_STATE_DIR",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
        }
    ),
    "aptl-soar": frozenset(
        {
            "APTL_HP_SHUFFLE_FRONTEND_443",
            "APTL_MCP_ADMITTED_RUN_ID",
            "APTL_MCP_RUN_STORE_BASE",
            "APTL_STATE_DIR",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
        }
    ),
    "aptl-threatintel": frozenset(
        {
            "APTL_HP_MISP_443",
            "APTL_MCP_ADMITTED_RUN_ID",
            "APTL_MCP_RUN_STORE_BASE",
            "APTL_STATE_DIR",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
        }
    ),
    "aptl-wazuh": frozenset(
        {
            "APTL_HP_WAZUH_INDEXER_9200",
            "APTL_HP_WAZUH_MANAGER_55000",
            "APTL_MCP_ADMITTED_RUN_ID",
            "APTL_MCP_RUN_STORE_BASE",
            "APTL_STATE_DIR",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
        }
    ),
}


class ClaudeCodeHostParticipantAdapter:
    """Use the operator's authenticated Claude Code CLI for one bounded turn."""

    def __init__(
        self,
        executable: Path,
        work_dir: Path,
        *,
        runner: ProcessRunner | None = None,
        timeout_seconds: float = 600.0,
        max_output_bytes: int = 2_000_000,
    ) -> None:
        """Admit an installed executable and bind its bounded runner."""

        self._executable = _admitted_executable(executable)
        self._work_dir = work_dir.resolve()
        self._host_home = _host_home()
        self._runner = runner or BoundedProcessRunner()
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes

    def deliver(
        self,
        *,
        instruction: str,
        model: str,
        config_path: Path,
        allowed_tools: tuple[str, ...],
        session_id: str,
        resume: bool,
    ) -> ParticipantTurnResult:
        """Deliver one instruction through the authenticated host CLI."""

        if not instruction.strip():
            raise AgentExecutionError("participant instruction is empty")
        config_digest = _private_file_sha256(config_path)
        argv = self._argv(
            model=model,
            config_path=config_path,
            allowed_tools=allowed_tools,
            session_id=session_id,
            resume=resume,
        )
        environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            # The host participant is the operator's installed, authenticated
            # Claude CLI. Its login can depend on provider state below HOME
            # (for example Google ADC), so retain that one host coordinate.
            "HOME": str(self._host_home),
            "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
            "NO_COLOR": "1",
            **{
                name: os.environ[name]
                for name in (
                    *_PROVIDER_AUTH_ENVIRONMENT,
                    "XDG_CONFIG_HOME",
                    "CLAUDE_CONFIG_DIR",
                )
                if os.environ.get(name)
            },
        }
        result = self._runner.run(
            argv,
            env=environment,
            cwd=self._work_dir,
            stdin=instruction.encode("utf-8"),
            timeout_seconds=self._timeout_seconds,
            max_output_bytes=self._max_output_bytes,
        )
        if not hmac.compare_digest(config_digest, _private_file_sha256(config_path)):
            raise AgentExecutionError(
                "participant MCP configuration changed during delivery"
            )
        if result.returncode != 0:
            raise AgentExecutionError("participant instruction delivery failed")
        response = _parse_agent_result(result.stdout)
        payload = json.loads(result.stdout)
        return ParticipantTurnResult(
            session_id=session_id,
            response=response,
            provider_payload=payload,
        )

    def _argv(
        self,
        *,
        model: str,
        config_path: Path,
        allowed_tools: tuple[str, ...],
        session_id: str,
        resume: bool,
    ) -> tuple[str, ...]:
        """Build the bounded noninteractive CLI argument vector."""

        session_args = (
            ("--resume", session_id) if resume else ("--session-id", session_id)
        )
        return (
            str(self._executable),
            "--print",
            "--bare",
            "--disable-slash-commands",
            "--no-chrome",
            "--output-format",
            "json",
            "--permission-mode",
            "dontAsk",
            "--tools",
            "",
            "--model",
            model,
            "--allowedTools",
            ",".join(allowed_tools),
            "--mcp-config",
            str(config_path),
            "--strict-mcp-config",
            *session_args,
        )


def _render_runtime_profile_config(
    *,
    profile: ProfileId,
    project_dir: Path,
    source_config: Path,
    output_dir: Path,
    node_executable: Path,
) -> tuple[Path, tuple[str, ...]]:
    """Render one private MCP config containing only a role's admitted tools."""

    source_servers = _load_source_servers(source_config)
    servers: dict[str, object] = {}
    allowed: list[str] = []
    for server in profile_for(profile).servers:
        server_id, rendered, tools = _render_profile_server(
            server, source_servers, project_dir, node_executable
        )
        servers[server_id] = rendered
        allowed.extend(tools)
    path = output_dir / f"{profile.value}.mcp.json"
    create_exclusive_nofollow(
        output_dir,
        path.name,
        (json.dumps({"mcpServers": servers}, sort_keys=True) + "\n").encode(),
    )
    return path, tuple(allowed)


def _load_source_servers(source_config: Path) -> dict[str, object]:
    """Load the synchronized MCP server map from one private config."""

    try:
        document = json.loads(source_config.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AgentExecutionError(
            "synchronized MCP configuration is unreadable"
        ) from exc
    servers = document.get("mcpServers") if isinstance(document, dict) else None
    if not isinstance(servers, dict):
        raise AgentExecutionError("synchronized MCP configuration is invalid")
    return servers


def _render_profile_server(
    server: object,
    source_servers: dict[str, object],
    project_dir: Path,
    node_executable: Path,
) -> tuple[str, dict[str, object], tuple[str, ...]]:
    """Validate and render one admitted MCP server declaration."""

    server_id = server.server_id
    source = source_servers.get(server_id)
    if not isinstance(source, dict) or not isinstance(source.get("env"), dict):
        raise AgentExecutionError("participant profile MCP server is unavailable")
    source_environment = source["env"]
    admitted_environment = _MCP_RUNTIME_ENVIRONMENT.get(server_id)
    if admitted_environment is None:
        raise AgentExecutionError("participant profile MCP environment is unsupported")
    allowed_environment = (
        _MCP_COMMON_RUNTIME_ENVIRONMENT
        | admitted_environment
        | frozenset(server.credential_aliases)
    )
    if set(source_environment) - allowed_environment:
        raise AgentExecutionError("participant profile MCP environment is not admitted")
    if set(server.credential_aliases) - set(source_environment):
        raise AgentExecutionError(
            "participant profile MCP credential environment is incomplete"
        )
    artifact = (project_dir / server.artifact_ref).resolve()
    if not artifact.is_file() or not artifact.is_relative_to(project_dir.resolve()):
        raise AgentExecutionError("participant profile MCP artifact is unavailable")
    rendered = {
        "command": str(node_executable),
        "args": [str(artifact)],
        "env": {
            name: value
            for name, value in source_environment.items()
            if name in allowed_environment
        },
    }
    tools = tuple(f"mcp__{server_id}__{tool}" for tool in server.tool_names)
    return server_id, rendered, tools


def _private_file_sha256(path: Path) -> str:
    """Hash one private config after enforcing its filesystem boundary."""

    return hashlib.sha256(_read_private_config(path)).hexdigest()


def _host_home() -> Path:
    """Return the authenticated host CLI home without reading its contents."""

    value = os.environ.get("HOME", "")
    path = Path(value)
    if not value or not path.is_absolute() or not path.is_dir():
        raise AgentExecutionError("authenticated participant CLI home is unavailable")
    return path.resolve()


def _which_executable(name: str) -> Path:
    """Resolve a required host executable without executing it."""

    candidate = shutil.which(name)
    if candidate is None:
        raise AgentExecutionError(
            f"required participant executable is unavailable: {name}"
        )
    return Path(candidate)
