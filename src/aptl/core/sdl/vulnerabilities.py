"""Vulnerability models — CWE-classified vulnerabilities.

Each vulnerability is classified by its CWE identifier (e.g., CWE-89
for SQL injection). The class field is validated against a regex.
"""

import re

from pydantic import Field, field_validator

from aptl.core.sdl._base import SDLModel

_CWE_PATTERN = re.compile(r"^CWE-\d+$")


class Vulnerability(SDLModel):
    """A named vulnerability with CWE classification."""

    name: str
    description: str
    technical: bool = False
    vuln_class: str = Field(alias="class")

    @field_validator("vuln_class")
    @classmethod
    def validate_cwe_format(cls, v: str) -> str:
        if not _CWE_PATTERN.match(v):
            raise ValueError(
                f"Vulnerability class must match CWE-NNN format, got: {v!r}"
            )
        return v
