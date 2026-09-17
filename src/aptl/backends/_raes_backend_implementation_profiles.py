"""Select APTL backend implementations from portable runtime semantics."""

from __future__ import annotations

from aptl.backends._raes_backend_implementation_catalog import (
    BACKEND_IMPLEMENTATION_PROFILES,
    NODE22_SYSTEMD_BASE_IMAGE,
    SAMBA_AD_BASE_IMAGE,
    WAZUH_DEBIAN_BASE_IMAGE,
    WAZUH_DEBIAN_SYSTEMD_BASE_IMAGE,
    WAZUH_RHEL_SYSTEMD_BASE_IMAGE,
    WAZUH_SAMBA_AD_BASE_IMAGE,
)
from aptl.backends._raes_backend_implementation_types import (
    BackendBaseSelection,
    BackendImplementationProfile,
    SemanticRuntimeSelector,
)


def selected_backend_base_image(runtime: object) -> str | None:
    """Return the narrow local substrate selected by portable requirements."""

    selection = selected_backend_base(runtime)
    return selection.image_ref if selection is not None else None


def selected_backend_base(
    runtime: object, services: tuple[object, ...] = ()
) -> BackendBaseSelection | None:
    """Return a substrate/provider selected from portable runtime semantics."""

    candidates = (
        _node22_ssh_base(runtime),
        _active_directory_base(runtime),
        _wazuh_agent_base(runtime, services),
    )
    return next((candidate for candidate in candidates if candidate is not None), None)


def _node22_ssh_base(runtime: object) -> BackendBaseSelection | None:
    """Select the generic systemd Node.js base for a declared SSH node."""

    node22 = any(
        getattr(component, "component_id", "") == "nodejs"
        and str(getattr(component, "version", "")) == "22"
        for component in getattr(runtime, "software_components", ())
    )
    needs_ssh = any(
        getattr(unit, "unit_name", "") in {"ssh.service", "sshd.service"}
        for unit in getattr(runtime, "service_manager_units", ())
    )
    return (
        BackendBaseSelection(image_ref=NODE22_SYSTEMD_BASE_IMAGE)
        if node22 and needs_ssh
        else None
    )


def _active_directory_base(runtime: object) -> BackendBaseSelection | None:
    """Select the Samba provider base for one complete domain authority."""

    listener_services = {
        _plain_value(getattr(listener, "service", ""))
        for listener in getattr(runtime, "service_listeners", ())
    }
    domain_authorities = [
        authority
        for authority in getattr(runtime, "identity_authorities", ())
        if _complete_domain_authority(authority)
    ]
    if (
        not {"kerberos", "ldap", "smb"} <= listener_services
        or len(domain_authorities) != 1
    ):
        return None
    authority = domain_authorities[0]
    realm = str(authority.realm).upper()
    image_ref = (
        WAZUH_SAMBA_AD_BASE_IMAGE if _has_wazuh_agent(runtime) else SAMBA_AD_BASE_IMAGE
    )
    return BackendBaseSelection(
        image_ref=image_ref,
        use_image_command=True,
        run_capabilities=("SYS_ADMIN",),
        provider_kind="samba-active-directory",
        provider_parameters=(("domain", realm.partition(".")[0]), ("realm", realm)),
    )


def _complete_domain_authority(authority: object) -> bool:
    """Return whether an authority has the portable Samba selection identity."""

    return bool(
        _plain_value(getattr(authority, "kind", "")) == "domain"
        and getattr(authority, "realm", "")
        and getattr(authority, "domain_name", "")
    )


def _has_wazuh_agent(runtime: object) -> bool:
    """Return whether the runtime declares a Wazuh forwarding agent."""

    return any(
        _plain_value(getattr(agent, "implementation", "")) == "wazuh_agent"
        for agent in getattr(runtime, "forwarding_agents", ())
    )


def _wazuh_agent_base(
    runtime: object, services: tuple[object, ...]
) -> BackendBaseSelection | None:
    """Select the minimum Wazuh-capable base and optional Flask provider."""

    if not _has_wazuh_agent(runtime):
        return None
    image_ref = _wazuh_base_image(runtime)
    application = _flask_application_provider(runtime, services)
    provider_kind = "python-flask-application" if application else "wazuh-agent"
    return BackendBaseSelection(
        image_ref=image_ref,
        provider_kind=provider_kind,
        provider_parameters=application or (),
    )


def _wazuh_base_image(runtime: object) -> str:
    """Choose the Wazuh base by package family and service-manager need."""

    rhel = any(
        getattr(package, "manager", "") in {"dnf", "yum"}
        for package in getattr(runtime, "packages", ())
    )
    runs_services = bool(getattr(runtime, "service_manager_units", ()))
    if rhel and runs_services:
        return WAZUH_RHEL_SYSTEMD_BASE_IMAGE
    return WAZUH_DEBIAN_SYSTEMD_BASE_IMAGE if runs_services else WAZUH_DEBIAN_BASE_IMAGE


def _flask_application_provider(
    runtime: object, services: tuple[object, ...]
) -> tuple[tuple[str, str], ...] | None:
    """Select the minimum local provider for one declared Flask HTTP app."""

    applications = [
        item
        for item in getattr(runtime, "applications", ())
        if _plain_value(getattr(item, "framework", "")).lower() == "flask"
        and getattr(item, "service", None)
    ]
    if len(applications) != 1:
        return None
    service_name = _plain_value(applications[0].service)
    ports = [
        item
        for item in services
        if getattr(item, "name", None) == service_name
        and getattr(item, "protocol", "tcp") == "tcp"
        and isinstance(getattr(item, "port", None), int)
    ]
    if len(ports) != 1:
        return None
    return (
        ("application_id", str(applications[0].application_id)),
        ("module", "app:app"),
        ("port", str(ports[0].port)),
        ("workdir", "/app"),
    )


def matching_backend_implementation_profile(
    runtime: object,
) -> BackendImplementationProfile | None:
    """Return the unique profile matching portable runtime semantics."""

    matches = [
        profile
        for profile in BACKEND_IMPLEMENTATION_PROFILES
        if _selector_matches(runtime, profile.selector)
    ]
    return matches[0] if len(matches) == 1 else None


def backend_profile_selected_concerns(runtime: object) -> frozenset[str]:
    """Return the concerns APTL would select for a matching semantic runtime."""

    profile = matching_backend_implementation_profile(runtime)
    concerns = (
        {"compute-substrate", *profile.runtime_selections}
        if profile is not None
        else set()
    )
    if selected_backend_base(runtime) is not None:
        concerns.add("compute-substrate")
    return frozenset(concerns)


def _selector_matches(runtime: object, selector: SemanticRuntimeSelector) -> bool:
    """Return whether one portable runtime record matches a profile selector."""

    return any(
        _record_matches(record, selector)
        for record in getattr(runtime, selector.collection, ())
    )


def _record_matches(record: object, selector: SemanticRuntimeSelector) -> bool:
    """Match a selector against one typed runtime record."""

    value = _plain_value(getattr(record, selector.field_name, ""))
    version = _plain_value(getattr(record, "version", ""))
    return value == selector.value and (
        not selector.version or version == selector.version
    )


def _plain_value(value: object) -> str:
    """Read enum-like values without coupling profile selection to enum types."""

    return str(getattr(value, "value", value) or "")


__all__ = (
    "BACKEND_IMPLEMENTATION_PROFILES",
    "BackendBaseSelection",
    "BackendImplementationProfile",
    "NODE22_SYSTEMD_BASE_IMAGE",
    "SAMBA_AD_BASE_IMAGE",
    "WAZUH_DEBIAN_BASE_IMAGE",
    "WAZUH_DEBIAN_SYSTEMD_BASE_IMAGE",
    "WAZUH_RHEL_SYSTEMD_BASE_IMAGE",
    "WAZUH_SAMBA_AD_BASE_IMAGE",
    "SemanticRuntimeSelector",
    "backend_profile_selected_concerns",
    "matching_backend_implementation_profile",
    "selected_backend_base_image",
    "selected_backend_base",
)
