# Historical Runtime Architecture Note

This page is retained only for older ADR links. The APTL-local SDL compiler,
planner, and runtime target registry described by the old version of this page
were removed after the ADR-035 ACES SDL cutover.

The supported runtime handoff is now:

1. Resolve the curated catalog ID or explicit project-contained SDL path.
2. Validate the selected file with `aces_sdl.parse_sdl_file`.
3. Plan through `aces_runtime.manager.RuntimeManager`.
4. Start the lab through `aptl.backends.aces.start_aces_scenario()`.

APTL still keeps `aptl.core.runtime.workflow_engine` as an implementation
helper for the ACES orchestrator's workflow result/history records. It is not a
scenario parser, compiler, planner, or schema authority.
