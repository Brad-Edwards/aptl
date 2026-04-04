"""Shared Source reference type.

A Source identifies an artifact (VM image, package, template) by
name and version. Supports shorthand (bare string) and longhand
(name + version dict) forms matching OCR SDL conventions.

The Source is backend-agnostic: it could reference a Docker image,
VM template, OVA, AMI, or any provider-specific artifact. Resolution
is delegated to the deployment backend.
"""

from pydantic import Field

from aptl.core.sdl._base import SDLModel


class Source(SDLModel):
    """Provider-neutral artifact reference.

    Shorthand: ``source: "package-name"`` (version defaults to ``"*"``).
    Longhand: ``source: {name: "package-name", version: "1.2.3"}``.
    """

    name: str
    version: str = Field(default="*")
