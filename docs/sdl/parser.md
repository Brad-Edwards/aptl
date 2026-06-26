# Historical Parser Note

This page is retained only so older ADRs and review notes have a stable target.
The APTL-local parser described here was removed after the ADR-035 ACES SDL
cutover.

Current scenario validation is delegated to `aces_sdl.parse_sdl_file` through
the startup catalog and ACES runtime handoff. New scenario-authoring work must
use ACES SDL docs and the APTL ACES validation gates, not a local parser API.
