"""Read back TechVault's generated Redis ACL without disclosing its credential."""

from __future__ import annotations

from typing import TYPE_CHECKING

from aptl.backends._runtime_concern_disclosure import _disclose
from aptl.core.deployment._misp_cache_credential import MISP_CACHE_RUNTIME_CONFIG_PATH

if TYPE_CHECKING:
    from raes.runtime_configuration import RuntimeConfiguration

    from aptl.core.deployment.backend import DeploymentBackend


# The selected Redis provider stages its owner-only config at this path. The
# script reads the password inside the guest and gives it to redis-cli through
# its environment, never argv or the observation result. The application user
# cannot run administrative introspection commands, so the exact loaded config
# is corroborated by authenticated read/write and denied-admin probes instead.
_REDIS_ACL_READBACK_SCRIPT = r"""
set -eu
pass="$(sed -nE 's/^user default reset on >([A-Za-z0-9_-]+) .+$/\1/p' __APTL_REDIS_CONFIG__)"
[ -n "$pass" ]
expected="user default reset on >$pass ~* +@read +@write +@connection +@transaction -@dangerous"
expected_hash="$(printf '%s\nappendonly no\nmaxmemory-policy noeviction\n' "$expected" | sha256sum)"
actual_hash="$(sha256sum __APTL_REDIS_CONFIG__)"
[ "${expected_hash%% *}" = "${actual_hash%% *}" ]
unauth="$(redis-cli --raw PING 2>&1)"
case "$unauth" in NOAUTH*) ;; *) exit 1 ;; esac
REDISCLI_AUTH="$pass"
export REDISCLI_AUTH
[ "$(redis-cli --raw PING)" = PONG ]
probe_key="__aptl_acl_probe__:$(date +%s):$$"
[ "$(redis-cli --raw SET "$probe_key" aptl EX 30)" = OK ]
[ "$(redis-cli --raw GET "$probe_key")" = aptl ]
[ "$(redis-cli --raw DEL "$probe_key")" = 1 ]
acl_result="$(redis-cli --raw ACL GETUSER default 2>&1)"
case "$acl_result" in *NOPERM*) ;; *) exit 1 ;; esac
config_result="$(redis-cli --raw CONFIG GET requirepass 2>&1)"
case "$config_result" in *NOPERM*) ;; *) exit 1 ;; esac
echo 'config=exact'
echo 'auth=PONG'
echo 'rw=verified'
echo 'admin=denied'
""".strip().replace("__APTL_REDIS_CONFIG__", MISP_CACHE_RUNTIME_CONFIG_PATH)


def observe_redis_app_authorizations(
    backend: "DeploymentBackend",
    container_name: str,
    runtime: "RuntimeConfiguration",
) -> object | None:
    """Corroborate the supported read/write authorization against live Redis."""

    authorizations = tuple(runtime.app_authorizations)
    if len(authorizations) != 1 or not _supported_read_write_acl(authorizations[0]):
        return None
    result = backend.container_exec(
        container_name, ["sh", "-ec", _REDIS_ACL_READBACK_SCRIPT], timeout=30
    )
    if getattr(result, "returncode", 1) != 0 or not _readback_verified(result):
        return None
    return _disclose(
        "runtime-app-authorizations",
        [item.model_dump(mode="json", by_alias=True) for item in authorizations],
    )


def _readback_verified(result: object) -> bool:
    """Require the bounded guest probe's four exact classified outcomes."""

    lines = str(getattr(result, "stdout", "") or "").splitlines()
    if len(lines) != 4 or any("=" not in line for line in lines):
        return False
    pairs = (line.split("=", 1) for line in lines)
    fields = {name: value for name, value in pairs}
    return fields == {
        "config": "exact",
        "auth": "PONG",
        "rw": "verified",
        "admin": "denied",
    }


def _supported_read_write_acl(authorization: object) -> bool:
    """Map one logical service account to MISP's password-only Redis client."""

    principals = tuple(getattr(authorization, "principals", ()))
    roles = tuple(getattr(authorization, "roles", ()))
    grants = tuple(getattr(authorization, "permission_grants", ()))
    mappings = tuple(getattr(authorization, "role_mappings", ()))
    if (
        _value(getattr(authorization, "resource_vocabulary", "")) != "redis_acl"
        or getattr(authorization, "auth_enabled", None) is not True
        or any(len(items) != 1 for items in (principals, roles, grants, mappings))
        or getattr(authorization, "tenants", ())
    ):
        return False
    principal, role, grant, mapping = (
        principals[0],
        roles[0],
        grants[0],
        mappings[0],
    )
    principal_id = getattr(principal, "principal_id", "")
    role_id = getattr(role, "role_id", "")
    return bool(
        principal_id
        and role_id
        and _principal_matches(principal)
        and _grant_mapping_matches(grant, mapping, principal_id, role_id)
    )


def _principal_matches(principal: object) -> bool:
    """Require one password-only default Redis service account."""

    return bool(
        _value(getattr(principal, "kind", "")) == "service_account"
        and _value(getattr(principal, "credential_classification", ""))
        in {"redacted", "operator_secret"}
        and getattr(principal, "name", "") in {"", "default"}
        and not getattr(principal, "backend_roles", ())
    )


def _grant_mapping_matches(
    grant: object, mapping: object, principal_id: str, role_id: str
) -> bool:
    """Require exactly read/write access without Redis administration."""

    return bool(
        getattr(grant, "role_ref", "") == role_id
        and _value(getattr(grant, "resource_kind", "")) == "redis_acl"
        and _value(getattr(grant, "effect", "")) == "allow"
        and set(getattr(grant, "actions", ())) == {"read", "write"}
        and tuple(getattr(grant, "resource_patterns", ())) == ("*",)
        and getattr(mapping, "role_ref", "") == role_id
        and tuple(getattr(mapping, "users", ())) == (principal_id,)
        and not getattr(mapping, "backend_roles", ())
        and not getattr(mapping, "hosts", ())
    )


def _value(value: object) -> str:
    """Normalize RAES enum-like values for exact ACL declaration checks."""

    return str(getattr(value, "value", value) or "")
