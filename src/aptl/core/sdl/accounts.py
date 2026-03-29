"""Account models — user accounts within scenario systems.

Adapted from CyRIS ``add_account``/``modify_account`` and CybORG
agent session definitions. Describes accounts that exist on
scenario nodes — AD users, database users, SSH users, email
accounts — including properties relevant to attack scenarios
(password strength, Kerberos SPNs, group memberships).
"""

from enum import Enum

from pydantic import Field, field_validator

from aptl.core.sdl._base import SDLModel, normalize_enum_value


class PasswordStrength(str, Enum):
    """How resistant the account password is to cracking."""

    WEAK = "weak"
    MEDIUM = "medium"
    STRONG = "strong"
    NONE = "none"


class Account(SDLModel):
    """A user account on a scenario node.

    Distinct from OCR's ``Role`` model: roles map exercise participants
    to VM logins for exercise access. Accounts describe the environment
    state — what accounts attackers will encounter or exploit.
    """

    username: str
    node: str = ""
    groups: list[str] = Field(default_factory=list)
    password_strength: PasswordStrength = PasswordStrength.MEDIUM
    auth_method: str = "password"
    description: str = ""
    mail: str = ""
    spn: str = ""
    shell: str = ""
    home: str = ""
    disabled: bool = False

    @field_validator("password_strength", mode="before")
    @classmethod
    def normalize_strength(cls, v: str) -> str:
        return normalize_enum_value(v)
