"""Process-resource capabilities published by the APTL backend manifest."""

from raes_contracts.apparatus import ProcessResourceLimitCapability
from raes_contracts.vocabulary import (
    ProcessResourceLimitKind,
    ProcessResourceLimitScope,
)

APTL_PROCESS_RESOURCE_LIMITS = (
    ProcessResourceLimitCapability(
        resource=ProcessResourceLimitKind.OPEN_FILE_DESCRIPTORS,
        scopes=frozenset({ProcessResourceLimitScope.SUBTREE}),
        minimum=0,
        maximum=None,
        supports_unlimited=True,
    ),
    ProcessResourceLimitCapability(
        resource=ProcessResourceLimitKind.LOCKED_MEMORY_BYTES,
        scopes=frozenset({ProcessResourceLimitScope.SUBTREE}),
        minimum=0,
        maximum=None,
        supports_unlimited=True,
    ),
)

__all__ = ("APTL_PROCESS_RESOURCE_LIMITS",)
