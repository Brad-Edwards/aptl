"""Backend-capability validation for compiled runtime models."""

from aptl.core.runtime.capabilities import ProvisionerCapabilities
from aptl.core.runtime.models import (
    Diagnostic,
    NodeRuntime,
    ResolvedResource,
    RuntimeModel,
    Severity,
)
from aptl.core.sdl._base import (
    extract_variable_name,
    parse_enum_or_var,
    parse_int_or_var,
)
from aptl.core.sdl.infrastructure import MINIMUM_NODE_COUNT
from aptl.core.sdl.nodes import OSFamily


def _variable_ref(
    model: RuntimeModel,
    value: object,
) -> tuple[str | None, dict[str, object] | None, bool]:
    """Resolve a value to its referenced variable name, spec, and declared flag."""
    variable_name = extract_variable_name(value) if isinstance(value, str) else None
    if variable_name is None:
        return None, None, False
    spec = model.variable_specs.get(variable_name)
    if isinstance(spec, dict):
        return variable_name, spec, True
    return variable_name, None, False


def _error_diagnostic(code: str, address: str, message: str) -> Diagnostic:
    """Build a provisioning-domain error diagnostic."""
    return Diagnostic(
        code=code,
        domain="provisioning",
        address=address,
        message=message,
    )


def _variable_default_suffix(
    variable_name: str,
    variable_spec: dict[str, object] | None,
) -> str:
    """Render the trailing deferral note describing a variable's default."""
    if variable_spec is None or variable_spec.get("default") is None:
        return f" Variable '{variable_name}' has no finite pre-instantiation domain."
    return (
        f" Variable '{variable_name}' has default {variable_spec['default']!r}, "
        "but defaults are informative only before instantiation."
    )


def _warning_diagnostic(code: str, address: str, message: str) -> Diagnostic:
    """Build a provisioning-domain warning diagnostic."""
    return Diagnostic(
        code=code,
        domain="provisioning",
        address=address,
        message=message,
        severity=Severity.WARNING,
    )


def _parse_os_allowed_value(
    raw_value: object,
    variable_name: str,
    address: str,
) -> tuple[str | None, Diagnostic | None, bool]:
    """Parse one OS allowed value into (validated value, diagnostic, defer flag)."""
    try:
        parsed = parse_enum_or_var(raw_value, OSFamily, field_name="os")
    except ValueError as exc:
        invalid_detail: str = f"invalid for nodes.os: {exc}."
    else:
        if extract_variable_name(parsed) is not None:
            return None, None, True
        if isinstance(parsed, OSFamily):
            return parsed.value, None, False
        invalid_detail = "that could not be validated for nodes.os."

    diagnostic = _error_diagnostic(
        "provisioner.os-family-variable-domain-invalid",
        address,
        (
            "Variable "
            f"'{variable_name}' allowed_values contain value {raw_value!r} "
            f"{invalid_detail}"
        ),
    )
    return None, diagnostic, False


def _validate_os_allowed_values(
    variable_name: str,
    variable_spec: dict[str, object],
    *,
    address: str,
) -> tuple[tuple[str, ...] | None, Diagnostic | None]:
    """Validate a variable's OS-family allowed values, returning the finite domain."""
    allowed_values = variable_spec.get("allowed_values")
    if not isinstance(allowed_values, list) or not allowed_values:
        return None, None

    validated_values: list[str] = []
    for raw_value in allowed_values:
        value, diagnostic, defer = _parse_os_allowed_value(
            raw_value, variable_name, address
        )
        if diagnostic is not None or defer:
            result = (None, diagnostic)
            break
        if value is not None:
            validated_values.append(value)
    else:
        result = (tuple(validated_values), None)
    return result


def _os_family_unsupported_diagnostics(
    node: NodeRuntime,
    variable_name: str,
    finite_domain: tuple[str, ...],
    supported_os_families: frozenset[str],
) -> list[Diagnostic]:
    """Report OS families allowed by a variable that the provisioner cannot support."""
    unsupported_values = sorted(
        {value for value in finite_domain if value not in supported_os_families}
    )
    if not unsupported_values:
        return []
    rendered = ", ".join(repr(value) for value in unsupported_values)
    return [
        Diagnostic(
            code="provisioner.unsupported-os-family",
            domain="provisioning",
            address=node.address,
            message=(
                "Provisioner does not support all OS families allowed by "
                f"variable '{variable_name}': {rendered}."
            ),
        )
    ]


def _literal_os_family_diagnostics(
    node: NodeRuntime,
    supported_os_families: frozenset[str],
) -> list[Diagnostic]:
    """Validate a literal (non-variable) node OS family against provisioner support."""
    if node.os_family in supported_os_families:
        return []
    return [
        Diagnostic(
            code="provisioner.unsupported-os-family",
            domain="provisioning",
            address=node.address,
            message=f"Provisioner does not support OS family '{node.os_family}'.",
        )
    ]


def _variable_os_family_diagnostics(
    node: NodeRuntime,
    variable_name: str,
    variable_spec: dict[str, object] | None,
    is_declared: bool,
    supported_os_families: frozenset[str],
) -> list[Diagnostic]:
    """Validate a variable-referenced node OS family against provisioner support."""
    if not is_declared:
        return [
            _error_diagnostic(
                "provisioner.os-family-variable-ref-unbound",
                node.address,
                (
                    "Provisioner capability validation cannot resolve undeclared "
                    f"variable '{variable_name}' referenced by nodes.os."
                ),
            )
        ]

    finite_domain, domain_error = _validate_os_allowed_values(
        variable_name,
        variable_spec or {},
        address=node.address,
    )
    if domain_error is not None:
        result = [domain_error]
    elif finite_domain is not None:
        result = _os_family_unsupported_diagnostics(
            node,
            variable_name,
            finite_domain,
            supported_os_families,
        )
    else:
        result = [
            _warning_diagnostic(
                "provisioner.os-family-validation-deferred",
                node.address,
                (
                    "Provisioner OS-family validation is deferred until "
                    f"instantiation for {node.os_family!r}."
                    f"{_variable_default_suffix(variable_name, variable_spec)}"
                ),
            )
        ]
    return result


def _validate_node_os_family(
    model: RuntimeModel,
    node: NodeRuntime,
    supported_os_families: frozenset[str],
) -> list[Diagnostic]:
    """Validate a node's OS family against provisioner support and variable domains."""
    if not node.os_family:
        return []

    variable_name, variable_spec, is_declared = _variable_ref(model, node.os_family)
    if variable_name is None:
        return _literal_os_family_diagnostics(node, supported_os_families)
    return _variable_os_family_diagnostics(
        node,
        variable_name,
        variable_spec,
        is_declared,
        supported_os_families,
    )


def _parse_count_allowed_value(
    raw_value: object,
    variable_name: str,
    address: str,
) -> tuple[int | None, Diagnostic | None, bool]:
    """Parse one count allowed value into (validated value, diagnostic, defer flag)."""
    try:
        parsed = parse_int_or_var(
            raw_value,
            minimum=MINIMUM_NODE_COUNT,
            field_name="count",
        )
    except ValueError as exc:
        invalid_detail: str = f"invalid for infrastructure.count: {exc}."
    else:
        if extract_variable_name(parsed) is not None:
            return None, None, True
        if isinstance(parsed, int):
            return parsed, None, False
        invalid_detail = "that could not be validated for infrastructure.count."

    diagnostic = _error_diagnostic(
        "provisioner.count-variable-domain-invalid",
        address,
        (
            "Variable "
            f"'{variable_name}' allowed_values contain value {raw_value!r} "
            f"{invalid_detail}"
        ),
    )
    return None, diagnostic, False


def _validate_count_allowed_values(
    variable_name: str,
    variable_spec: dict[str, object],
    *,
    address: str,
) -> tuple[int | None, Diagnostic | None]:
    """Validate a variable's count allowed values, returning the finite upper bound."""
    allowed_values = variable_spec.get("allowed_values")
    if not isinstance(allowed_values, list) or not allowed_values:
        return None, None

    validated_values: list[int] = []
    for raw_value in allowed_values:
        value, diagnostic, defer = _parse_count_allowed_value(
            raw_value, variable_name, address
        )
        if diagnostic is not None or defer:
            result = (None, diagnostic)
            break
        if value is not None:
            validated_values.append(value)
    else:
        result = (max(validated_values), None)
    return result


def _declared_count_upper_bound(
    resource: ResolvedResource,
    count: object,
    variable_name: str,
    variable_spec: dict[str, object] | None,
) -> tuple[int | None, Diagnostic | None]:
    """Resolve a declared count variable to its upper bound or deferral diagnostic."""
    finite_upper_bound, domain_error = _validate_count_allowed_values(
        variable_name,
        variable_spec or {},
        address=resource.address,
    )
    if domain_error is not None:
        return None, domain_error
    if finite_upper_bound is not None:
        return finite_upper_bound, None

    return (
        None,
        _warning_diagnostic(
            "provisioner.max-total-nodes-validation-deferred",
            resource.address,
            (
                "Provisioner max-total-nodes validation is deferred until "
                f"instantiation for {count!r}."
                f"{_variable_default_suffix(variable_name, variable_spec)}"
            ),
        ),
    )


def _resource_count_upper_bound(
    model: RuntimeModel,
    resource: ResolvedResource,
) -> tuple[int | None, Diagnostic | None]:
    """Resolve a resource's deployable-count upper bound or its deferral diagnostic."""
    count = resource.spec.get("infrastructure", {}).get("count", 1)
    if isinstance(count, int):
        return count, None

    variable_name, variable_spec, is_declared = _variable_ref(model, count)
    if variable_name is None:
        result: tuple[int | None, Diagnostic | None] = (None, None)
    elif not is_declared:
        unbound = _error_diagnostic(
            "provisioner.count-variable-ref-unbound",
            resource.address,
            (
                "Provisioner capability validation cannot resolve undeclared "
                f"variable '{variable_name}' referenced by infrastructure.count."
            ),
        )
        result = (None, unbound)
    else:
        result = _declared_count_upper_bound(
            resource,
            count,
            variable_name,
            variable_spec,
        )
    return result


def _account_features(account_spec: dict[str, object]) -> set[str]:
    """Derive the set of optional account features a placement spec requires."""
    features: set[str] = set()
    if account_spec.get("groups"):
        features.add("groups")
    if account_spec.get("mail"):
        features.add("mail")
    if account_spec.get("spn"):
        features.add("spn")
    if account_spec.get("shell"):
        features.add("shell")
    if account_spec.get("home"):
        features.add("home")
    disabled = account_spec.get("disabled")
    if disabled not in (False, None, ""):
        features.add("disabled")
    auth_method = account_spec.get("auth_method")
    if auth_method not in ("", None, "password"):
        features.add("auth_method")
    return features


def _validate_account_features(
    model: RuntimeModel,
    provisioner: ProvisionerCapabilities,
) -> list[Diagnostic]:
    """Validate account placements against the provisioner's account support."""
    diagnostics: list[Diagnostic] = []
    if model.account_placements and not provisioner.supports_accounts:
        diagnostics.append(
            Diagnostic(
                code="provisioner.accounts-unsupported",
                domain="provisioning",
                address="provision.accounts",
                message="Provisioner does not support accounts.",
            )
        )
    elif provisioner.supports_accounts:
        for account in model.account_placements.values():
            for feature in sorted(_account_features(account.spec)):
                if feature not in provisioner.supported_account_features:
                    diagnostics.append(
                        Diagnostic(
                            code="provisioner.unsupported-account-feature",
                            domain="provisioning",
                            address=account.address,
                            message=(
                                "Provisioner does not support account feature "
                                f"'{feature}'."
                            ),
                        )
                    )
    return diagnostics
