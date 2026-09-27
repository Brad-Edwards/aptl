"""Guest-side participant workbench profile and lifecycle contracts."""

from aptl.workbench.agent import (
    AgentExecutionError,
    BoundedProcessRunner,
    ClaudeCodeManagedAgentAdapter,
)
from aptl.workbench.credentials import (
    EphemeralCredentialBroker,
    WorkbenchCredentialError,
)
from aptl.workbench.profiles import (
    ProfileId,
    WorkbenchConfigurationError,
    profile_for,
    render_profile_config,
    verify_profile_tool_inventory,
)
from aptl.workbench.runtime import (
    ProfileLaunch,
    WorkbenchPaths,
    WorkbenchRuntime,
    WorkbenchStateError,
)

__all__ = [
    "AgentExecutionError",
    "ApplianceWorkbenchSettings",
    "BoundedProcessRunner",
    "ClaudeCodeManagedAgentAdapter",
    "EphemeralCredentialBroker",
    "ProfileId",
    "ProfileLaunch",
    "WorkbenchConfigurationError",
    "WorkbenchCredentialError",
    "WorkbenchPaths",
    "WorkbenchRuntime",
    "WorkbenchStateError",
    "create_appliance_workbench_app",
    "profile_for",
    "render_profile_config",
    "verify_profile_tool_inventory",
]


def __getattr__(name: str) -> object:
    """Keep the optional browser stack out of ordinary CLI imports."""
    if name in {
        "ApplianceWorkbenchSettings",
        "LocalWorkbenchSettings",
        "create_appliance_workbench_app",
        "create_local_workbench_app",
    }:
        from aptl.workbench import bootstrap

        return getattr(bootstrap, name)
    raise AttributeError(name)
