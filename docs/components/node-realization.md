# Node Realization Routes

APTL realizes each OS-bearing scenario node by one of two routes. Both routes
run the node as a Docker container started from a container image. The routes
differ in where the node's scenario state comes from.

## Base-container-materialized node

A **base-container-materialized node** declares runtime desired state in the
RAES SDL and has no node image of its own. APTL starts a **base container** for
it from a **base image** and then applies the declared packages, software,
content, identities, and services to that running container. Readback then
verifies the applied state.

The base image is a hard dependency. It is a real Docker image, either a
generic operating-system base or a verified backend-selected base under the
admitted substrate policy. APTL prepares or verifies it, then starts the base
container through Docker. The scenario's meaningful detail comes from the SDL,
not from the base image.

A node uses this route only when it has runtime desired state and no entry in
the realization's image list. A node that declares runtime inventory and also
resolves an image stays on the image-backed route.

## Image-backed node

An **image-backed node** runs its own admitted component image, either pulled
from a pinned reference or built from declared provenance. That image already
carries the node's software. APTL starts it as a Compose service and binds
declared content into it.

## Compose startup is a separate fact

Whether Compose starts a node and how APTL obtains the node's state are
separate questions. A base-container-materialized node never becomes a Compose
service: APTL starts its base container directly with Docker and scales any
Compose service stub with the same name to zero. A graph with no image-backed
node still uses Docker, even when `compose up` has nothing to start.

Content placed at an authored literal destination path reaches both routes.
The materializer writes it into a base container, and Compose binds it into an
image-backed node.

## Historical term

Before issue [#1193](https://github.com/Brad-Edwards/aptl/issues/1193), APTL
called base-container-materialized nodes "image-free." That name was wrong:
these nodes always start from a base image. ADR-048's title, older ADRs,
architecture preflight notes, reviews, and changelog entries keep the old term
as a historical record. Read "image-free" there as "base-container-materialized."

Issue #1193 renamed these code identifiers and contracts:

| Before | After |
| --- | --- |
| `aptl.validation.imagefree_gate` (`image_free_violations`, `assert_image_free`, `ImageFreeGateError`) | `aptl.validation.realization_declaration_gate` (`realization_declaration_violations`, `assert_realization_declared`, `RealizationDeclarationGateError`) |
| `aptl.core.deployment._compose_image_free_realization` | `aptl.core.deployment._compose_base_container_realization` |
| `aptl.backends.raes_image_free_content_realization` (`resolve_image_free_content_placement`) | `aptl.backends.raes_literal_content_realization` (`resolve_literal_content_placement`) |
| Diagnostic `aptl.provisioner.image-free-content-unsupported` | Diagnostic `aptl.provisioner.literal-content-unsupported` |

No serialized field carried the old term. The spec-level `image_free` flag
was removed earlier and stays removed.
