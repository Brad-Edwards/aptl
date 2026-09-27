# MCP Smoke-Test Protocol

The canonical hands-on MCP procedure is the
[Release Candidate Manual QA](../testing/smoke-test-plan.md). It contains the
release-blocking checks for `mcp-red`, `mcp-wazuh`, `mcp-indexer`, `mcp-soar`,
`mcp-casemgmt`, `mcp-threatintel`, `mcp-network`, and `mcp-reverse`, with a
separate result and evidence reference for both supported install paths.

The former protocol on this page predated the SDL-only runtime and duplicated
different pass criteria. It is retired. Automated smoke and integration tests
remain valuable regression evidence, but process startup, `tools/list`, a
container health result, or an automated test cannot replace the manual
target-backed operations required by the release record.
