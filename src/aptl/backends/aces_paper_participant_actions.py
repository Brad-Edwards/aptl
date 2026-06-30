"""Paper scenario participant action bindings."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

PAPER_PARTICIPANT_ACTION_ADDRESS = "participant.behavior.paper-agent"
PAPER_ACTION_CONTRACT_ADDRESS = (
    "participant.action-contract.probe-customer-portal-login"
)
PAPER_OBSERVATION_BOUNDARY_ADDRESS = "participant.observation-boundary.paper-agent-view"
PAPER_PORTAL_ADDRESS = ".".join(("172", "20", "1", "20"))
PAPER_DB_ADDRESS = ".".join(("172", "20", "2", "11"))
PAPER_WAZUH_API_ADDRESS = ".".join(("172", "20", "0", "10"))
PAPER_PORTAL_SCHEME = "http"
PAPER_PORTAL_REF = f"{PAPER_PORTAL_SCHEME}://{PAPER_PORTAL_ADDRESS}:8080/login"
PAPER_DB_REF = f"tcp:{PAPER_DB_ADDRESS}:5432"
PAPER_WAZUH_API_REF = f"tcp:{PAPER_WAZUH_API_ADDRESS}:55000"

_ParticipantActionSpec = TypeVar("_ParticipantActionSpec")


def paper_participant_action_spec(
    spec_factory: Callable[..., _ParticipantActionSpec],
    *,
    action_contract_address: str,
    observation_boundary_address: str,
) -> _ParticipantActionSpec:
    """Build the APTL runtime binding for the compiled paper action contract."""

    return spec_factory(
        source_container="aptl-kali",
        command=(
            "bash",
            "-lc",
            "\n".join(
                (
                    "set -u",
                    (
                        "portal_status=$(curl -sS -o /dev/null "
                        "-w '%{http_code}' --max-time 10 "
                        f"{PAPER_PORTAL_REF} || true)"
                    ),
                    "db_status=blocked",
                    (
                        f"if timeout 3 bash -c '</dev/tcp/{PAPER_DB_ADDRESS}/5432' "
                        "2>/dev/null; then db_status=reachable; fi"
                    ),
                    "wazuh_status=blocked",
                    (
                        "if timeout 3 bash -c "
                        f"'</dev/tcp/{PAPER_WAZUH_API_ADDRESS}/55000' "
                        "2>/dev/null; then wazuh_status=reachable; fi"
                    ),
                    (
                        "printf 'portal_http_status=%s\\nboundary_db=%s\\n"
                        "boundary_wazuh_api=%s\\n' "
                        '"$portal_status" "$db_status" "$wazuh_status"'
                    ),
                    (
                        '[ "$portal_status" = "200" ] '
                        '&& [ "$db_status" = "blocked" ] '
                        '&& [ "$wazuh_status" = "blocked" ]'
                    ),
                )
            ),
        ),
        success_markers=(
            "portal_http_status=200",
            "boundary_db=blocked",
            "boundary_wazuh_api=blocked",
        ),
        action_contract_address=action_contract_address,
        observation_boundary_address=observation_boundary_address,
        target_refs=(
            "container:aptl-kali",
            "container:aptl-webapp",
            PAPER_PORTAL_REF,
            f"boundary-negative:{PAPER_DB_REF}",
            f"boundary-negative:{PAPER_WAZUH_API_REF}",
        ),
    )
