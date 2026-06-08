# ADR-029: Control-Plane Secret Handling in Run Data and Local State

## Status

accepted

## Date

2026-05-10

## Context

APTL intentionally contains vulnerable lab targets and designed lab
credentials. Those values are different from operator/control-plane secrets
that let a user or automation control infrastructure, external services, or
private systems. Run data, snapshots, traces, exports, CLI JSON, and local
state are analysis artifacts, not credential stores.

Existing guardrails already cover part of the boundary:

- ADR-012 makes OpenTelemetry span attributes, snapshot JSON, CLI JSON output,
  and exported run artifacts subject to shared serialization-boundary
  redaction.
- `src/aptl/utils/redaction.py` and `mcp/aptl-mcp-common/src/redaction.ts`
  are the canonical redaction helpers for Python and TypeScript boundaries.
- `RangeSnapshot.to_dict()` redacts the Python snapshot DTO shape before JSON
  serialization.
- `traceToolCall()` redacts MCP tool arguments and responses before writing
  OTel span attributes.
- ADR-027 keeps red-team structured logging on the common MCP command boundary
  and requires the TypeScript redaction helper for command-bearing records.
- `src/aptl/utils/curl_safe.py` keeps bearer/API-token headers and request
  bodies out of process argv by writing temporary `0600` files for curl.
- ADR-028 keeps rendered service config under ignored state, out of checked-in
  `config/`, and out of snapshots/archives except as redacted data or hashes.

The remaining risk is concept confusion: a value can be an intentional target
credential in one context and still become a control-plane secret if it is
copied into an operator-facing artifact without classification or redaction.

## Decision

APTL separates secret-like values into two classes:

| Class | Examples | Artifact rule |
| --- | --- | --- |
| Designed-vulnerable target data | Lab user passwords, intentionally weak web/database credentials, captured CTF flags, hashes or credential dumps produced by target compromise, default credentials documented as part of the vulnerable range | May appear in target containers and evidence artifacts when needed for lab realism or scoring, but should still be minimized and redacted at generic serialization boundaries when shape alone cannot distinguish it from control-plane material. |
| Control-plane/operator secrets | Real API keys, service tokens, bearer tokens, cookies, JWTs, private SSH keys, private TLS keys, `.env` runtime secrets, generated service config secrets, cloud/S3 credentials, MCP client env secrets, replayable session identifiers | Must never appear unredacted in snapshots, OTel traces, exports, run archives, CLI output, logs, API error envelopes, or normal local-state artifacts. |

The invariant is: **control-plane/operator secrets are redacted before they
cross a serialization, observability, archive, CLI, API-response, or log
boundary.** File permissions, ignored paths, S3 bucket access controls, and
archive location are defense in depth only.

Use the existing shared helper for the boundary in the language that owns the
artifact. Do not add a second secret taxonomy, parallel DTO schema, custom
exception hierarchy, or call-site-only filter unless the canonical helper
cannot express the required shape and is extended first.

## Artifact Boundary Audit

| Path / surface | Can carry target data | Can carry control-plane secrets | Boundary status |
| --- | --- | --- | --- |
| `src/aptl/core/snapshot.py` / `RangeSnapshot.to_dict()` / `aptl lab status --json` / `--output` | Container names, ports, service endpoints, designed lab service credentials | Service credentials if endpoint DTOs include them; key path references are safe, private key bytes are not | Redaction is already at the DTO boundary through `redact(asdict(self))`; keep new snapshot fields behind `to_dict()`. |
| MCP `traceToolCall()` / OTel spans | Tool args, command lines, target evidence returned by tools | API tokens, cookies, auth headers, private keys, command-line passwords/hashes | Redaction is already at the common telemetry wrapper; individual MCP handlers must not bypass it. |
| `src/aptl/core/runstore.py` `write_json`, `write_jsonl`, `append_jsonl`, `copy_file` | Flags, alerts, logs, traces, scenario artifacts, target evidence | Any caller-provided JSON/JSONL/file content, including collector responses and copied files | Treat as the Python persistence serialization boundary for run archives. New run-artifact writes that can contain control-plane secrets must pass redacted objects or use a redacting write path before bytes hit disk. |
| `src/aptl/core/collectors.py` | Wazuh alerts, Suricata EVE, TheHive/MISP/Shuffle records, container logs, OTel spans | SOC API tokens in responses/errors, auth headers, cookies, service logs containing generated config or env, tool spans from Tempo | Collection should stay fault-tolerant and transport-safe, but persistence of collector output must use the shared redaction policy. Collector logs must report counts/status, not payload secrets. |
| `src/aptl/core/exporter.py` / local tar.gz / S3 export | All persisted run artifacts | Whatever reached the run directory | Exporter is a packaging boundary, not the canonical redactor. It must not be the first place secrets are sanitized; tests should prove runstore inputs are already safe. |
| `src/aptl/cli/runs.py` | Run IDs, scenario names, artifact paths, counts | Manifest fields if future code adds tokens, absolute paths can expose local layout but not secret values | CLI should display metadata only. Any future `--json` or content-viewing output must reuse redacted runstore/DTO shapes. |
| `aptl config show --json` | First-party configuration values | Should not contain `.env` secrets; future config fields might contain tokens if schema boundaries drift | `AptlConfig` remains the canonical non-secret config schema. Do not move runtime secrets from `.env` into `aptl.json` without an explicit secret-handling design. |
| `aptl lab continuity-audit --json` and `continuity-events.jsonl` | Firewall rules, target containers, continuity evidence | Usually no secrets; command/error strings could leak if backend output is copied verbatim in the future | Keep event schema narrow. Do not include raw backend command output unless redacted first. |
| `.aptl/trace-context.json`, `.aptl/session.json`, generated `.aptl/config/*` | Trace/session correlation IDs and generated lab config | Replayable IDs and generated service secrets | Keep under ignored state with restrictive permissions where applicable; do not archive or print generated secret-bearing config, and redact replayable IDs when they enter analysis artifacts. |

## Security Layers

- **Secret classification:** use the two classes above before deciding whether
  data may be shown, persisted, traced, or exported.
- **Serialization redaction:** Python artifacts use
  `src/aptl/utils/redaction.py`; MCP/TypeScript artifacts use
  `mcp/aptl-mcp-common/src/redaction.ts`. The helpers must stay shape-aligned,
  especially for command-line credential forms.
- **Command-line exposure:** use `curl_safe` for SOC API calls so bearer/API
  tokens and request bodies avoid process argv. Avoid new subprocess calls that
  put tokens, passwords, NTLM hashes, cookies, or private key material in argv.
- **Config and env binding:** `AptlConfig` owns durable non-secret config;
  `.env` parsing and placeholder validation belong to `src/aptl/core/env.py`.
  Generated secret-bearing config follows ADR-028.
- **Persistence and exports:** `LocalRunStore` owns run artifact writes;
  `exporter.py` packages already-safe artifacts. Do not rely on tar/S3/export
  code as the primary redaction point.
- **Observability and errors:** logs, OTel attributes, CLI output, API
  responses, and exception text may name the failed system, path, or validation
  layer, but not the secret value.
- **OS/filesystem exposure:** secret-bearing local state belongs under ignored
  paths with restrictive permissions. That does not relax the redaction
  invariant for copied, archived, printed, or traced forms.

## Extensibility

The extensibility seam is the shared redaction helper plus a single artifact
classification table. New artifact kinds should add one row to the boundary
audit and route through the existing language boundary. New command-line
credential forms should extend both redaction helpers and their mirror tests,
not one caller or one language only.

If future work needs different handling for designed target data versus
operator secrets, add explicit artifact metadata or a small caller-supplied
classification option at the redaction boundary. Do not infer safety from the
source container name alone.

## Non-Goals

- Do not remove intentional vulnerable target credentials from the lab.
- Do not make run artifacts complete forensic vaults for plaintext secrets.
- Do not redact every target username, host, port, file path, rule ID, or
  non-secret diagnostic field.
- Do not redesign OTel, OCSF red-team logging, run archive layout, or Docker
  Compose service configuration as part of secret classification.
- Do not treat export/S3 access controls, `.gitignore`, or `0600` permissions
  as a substitute for serialization-boundary redaction.

## Anti-Patterns

- Adding a new `sanitize_*` helper beside `redact()` for one artifact path.
- Redacting inside one CLI command while leaving the same DTO unsafe elsewhere.
- Letting `exporter.py` mutate archive contents to hide leaks that were already
  written to the run directory.
- Passing credentials, hashes, cookies, tokens, or private key material through
  process argv, logs, exception messages, or span attributes.
- Treating `.env`, generated config, target container data, run archive data,
  and OTel attributes as the same concept because they all contain
  credential-shaped strings.
- Copying TypeScript command redaction patterns into Python incompletely; the
  two helper test suites must prove parity for `--password value`,
  hydra-style `-p value`, Samba `user%pass`, Basic-auth `user:pass`, NTLM
  `-H <hash>`, LDAP bind passwords, and impacket positional credentials.
