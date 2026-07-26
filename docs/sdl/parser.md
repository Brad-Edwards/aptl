# Historical Parser Note

This page is retained only so older ADRs and review notes have a stable target.
The APTL-local parser described here was removed after the ADR-035 RAES SDL
cutover.

Current scenario validation is delegated to `raes.parse_sdl_file` through
the startup catalog and RAES runtime handoff. New scenario-authoring work must
use RAES SDL docs and the APTL RAES validation gates, not a local parser API.
