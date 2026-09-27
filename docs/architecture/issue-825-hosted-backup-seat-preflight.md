# Issue #825 Hosted Desktop Seat Preflight

This note sets the design guardrails for the Black Hat Arsenal hosted-seat
proof. It is guidance, not an implementation plan. The GitHub issue owns the
delivery shape: one Ubuntu EC2 VM, one Linux account, one Amazon DCV session,
one Caddy instance, and one hostname per participant.

No new ADR is needed. This is a tested AWS operator procedure, not a new APTL
deployment architecture. The main risks are replacing the issue's per-seat
topology with shared ingress, duplicating APTL readiness and configuration in
cloud scripts, or presenting a mutable developer-host recipe as a qualified
sealed appliance.

The pinned recipe must verify its exact syntax against the official
[DCV authentication](https://docs.aws.amazon.com/dcv/latest/adminguide/security-authentication.html),
[DCV parameter](https://docs.aws.amazon.com/dcv/latest/adminguide/config-param-ref.html),
[DCV EC2 licensing](https://docs.aws.amazon.com/dcv/latest/adminguide/setting-up-license.html),
and [Caddy reverse-proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)
contracts. Those vendor contracts are versioned inputs, not details to infer
from a previously working host.

## Architecture Decisions And Guardrails

- One logical seat is one EC2 instance. Caddy and DCV run on that same
  instance. `seat01.<lab-domain>` resolves to that instance; Caddy accepts
  public HTTP/HTTPS and proxies to `https://127.0.0.1:8443`. There is no shared
  gateway, load balancer, bastion, claim service, or cross-seat upstream map.
- The live proof creates or reuses exactly `seat01`. It must not launch
  `seat02` through `seat12`. The class procedure repeats one parameterized,
  admitted operation for the twelve canonical seat identifiers; it does not
  introduce fleet state or per-seat APTL choices.
- Amazon DCV, not Caddy, authenticates the participant. DCV uses `system`
  authentication through its Linux PAM service. The session owner and OS user
  are the same `seatNN` identity, and only that owner is authorized for the
  session. Caddy performs TLS termination and proxying only; do not add Basic
  Auth, forward an asserted identity, or create another APTL authentication
  system.
- DCV's TCP web endpoint binds only IPv4 and IPv6 loopback on port 8443.
  Disable the QUIC frontend because the browser path is TCP through Caddy and
  no public UDP path is required. Pin DCV's allowed HTTP host and WebSocket
  origin patterns to the exact seat hostname. Preserve the external Host and
  origin semantics through Caddy and validate the upstream TLS certificate;
  do not use `tls_insecure_skip_verify`.
- Caddy has one exact-host site block and one fixed loopback upstream. Its
  automatic-HTTPS state, admin endpoint, logs, and systemd privileges remain
  local and hardened. Port 80 exists only for the selected ACME challenge and
  HTTP-to-HTTPS redirect. Unknown hosts must not fall through to the seat.
- Each seat security group admits public TCP 80 and 443, plus TCP 22 only from
  the exact operator source CIDR. It admits no UDP 443, TCP/UDP 8443, RDP,
  Docker, victim, SOC, APTL API, observability, or management port. Do not
  assign public IPv6 unless the runbook validates and audits the equivalent
  IPv6 rules and negative probes.
- The host firewall is defense in depth; the security group is the mandatory
  outer enforcement layer. APTL deliberately publishes victim ports 8080 and
  5353 on wildcard host addresses, while its management ports are loopback
  only. Internet-negative probes must therefore cover actual runtime
  listeners, not assume every Docker publication is loopback.
- Caddy's 443 and DCV's 8443 conflict with APTL's default Wazuh-dashboard and
  MISP host ports. Reuse the existing `APTL_HP_*`/`resolve_host_ports()`
  mechanism and pin one common host-recipe override before every lab start.
  Do not stop Caddy/DCV, edit Compose, or make a different decision per seat.
- The seat account is a participant identity, not an operator identity. It
  receives no sudo, SSH authorization, or direct Docker socket membership.
  Operator SSH uses a separate key-authenticated account and remains
  source-restricted. The supported workbench/agent boundary owns participant
  access to MCP operations; granting Docker-root authority merely because the
  VM is disposable is not an acceptable shortcut.
- The host recipe pins Ubuntu AMI identity and owner, architecture, instance
  type, encrypted root volume size, APTL release/profile identity, coding-agent
  version, MCP artifacts, DCV/Caddy versions, and non-secret service
  configuration. A mutable package name, `latest`, or an arbitrary checkout is
  not a tested recipe. The current guided profile requires at least x86-64,
  8 vCPUs, 16 GiB RAM, and 100 GiB disk; the selected instance type must also
  include measured desktop/DCV headroom.
- The purpose-tagged `aptl-bh-test` host may be reused only after capturing a
  secret-free baseline and proving the trial will not read, modify, stash, or
  clean its unrelated source changes. Use a released/staged artifact and a
  separate runtime directory. Record every changed package, account, group,
  file, unit, firewall rule, security-group rule, IAM association, DNS record,
  and Caddy/DCV state needed to restore the host.
- A signed ADR-049 appliance image may supply the tested host payload, but a
  mutable Ubuntu recipe does not become an appliance merely by running on
  EC2. Unless release verification and appliance-boundary qualification pass,
  the evidence proves only this hosted contingency procedure and must not be
  cited as sealed-appliance parity.
- Amazon DCV on EC2 needs narrowly scoped access to its regional license
  object in S3. If an instance role is required, grant only the documented
  `s3:GetObject` resource for the `us-east-2` DCV license bucket and ledger it.
  Do not attach a general S3, SSM, deployment, or administrator role. Require
  IMDSv2 and an appropriate metadata hop limit.
- Failed-seat replacement is cold replacement under the same logical
  `seatNN` assignment: withdraw the assignment, terminate or restore the old
  trial host as appropriate, prove its issue-created mutable storage and
  access material are gone, launch the same recipe, update DNS, create a fresh
  passphrase, and rerun ingress plus semantic readiness. It is not an EC2
  reboot, inner lab reset, disk restore, or in-place repair.

## Cross-Cutting Incumbents To Reuse

| Concern | Canonical owner and required reuse |
| --- | --- |
| Hosted operational precedent | `docs/workshop/emergency-rollout.md` owns the existing AWS capacity, golden-host, assignment, and teardown lessons. Reuse those lessons, but replace its legacy RDP, claim-page, broad seven-MCP, and fleet assumptions with the issue's DCV/manual-assignment shape. |
| APTL host lifecycle | `aptl lab init`, `aptl lab start`, `aptl lab status`, `aptl lab info`, and `aptl lab stop -v` remain the only supported lab lifecycle entrypoints. `core.lab`'s `LabResult`, `StartupOutcome`, and `StartupDiagnostic` own inner startup truth; raw Compose commands and a second hosted lifecycle do not. |
| Host ports and exposure | `docker-compose.yml`, `src/aptl/core/host_ports.py`, `src/aptl/core/endpoints.py`, and `tests/test_docker_compose_port_bindings.py` own APTL host-port meanings and remapping. The security group intersects that runtime surface; it does not redefine it. |
| Profile and readiness | `ParticipantProfileManifest`, `ParticipantReadinessSuite`, `load_participant_profile()`, `run_participant_mcp_smoke()`, and `evaluate_participant_qualification()` own the guided browser, exact MCP inventory, and semantic red/blue checks. The current bounded MCP set is `aptl-red`, `aptl-indexer`, and `aptl-wazuh`, not the legacy seven-server list. |
| Coding agent boundary | `ClaudeCodeManagedAgentAdapter`, `WorkbenchRuntime`, `EphemeralCredentialBroker`, generated strict MCP config, and `BoundedProcessRunner` own the action-capable participant agent path. The current Codex adapter is decision-only and cannot be substituted as evidence of real MCP operation. |
| Configuration and generated state | Strict `AptlConfig`/`load_config()`, `load_dotenv()`, `EnvVars`, placeholder detection, ADR-025, and ADR-028 remain authoritative. AWS, DNS, DCV, Caddy, seat assignment, and operator inputs are not new `aptl.json`, `.env`, or RAES fields. |
| Secrets and process safety | ADR-029, `aptl.utils.redaction.redact()`, TypeScript redaction parity, `curl_safe`, `pathsafe`, owner-only atomic writers, and fixed argv-list subprocesses are mandatory precedents. Redaction does not cure a password already exposed through argv, environment, user data, shell history, or logs. |
| Persistence, errors, and evidence | `LocalRunStore` is the incumbent redacting structured persistence boundary for APTL run evidence. AWS procedure evidence remains a separate redacted operator record with stable step labels and bounded summaries; do not invent APTL DTOs, exceptions, or runstore schemas for a shell runbook. |
| Seat vocabulary | `validate_seat_id()` supplies the repository's bounded lowercase identifier precedent, but issue #825 narrows it further to `^seat(0[1-9]\|1[0-2])$`. Appliance `SeatRecord` and its overlay lifecycle are not cloud-instance state and must not be copied into an AWS ledger. |

## Security And Validation Passage

The intended procedure crosses every layer below. Passing one layer does not
waive another.

| Layer | Required behavior |
| --- | --- |
| Operator identity and input gate | Pin `--profile catalyst-dev` and `--region us-east-2` on every AWS call; reject configured SSO fields; verify the expected STS account/caller before mutation and again before teardown. Validate the exact seat ID, hostname suffix, hosted zone, AMI owner/state/architecture, instance type, subnet route, volume settings, key reference, operator single-host CIDR, and local tool versions. Never inspect or copy AWS credential files. |
| Recipe and supply chain admission | Record immutable Ubuntu AMI and APTL/profile identities plus tested DCV, Caddy, Docker, coding-agent, MCP, and package versions or digests. Use the profile's minimum hardware and asset closure. Unknown provenance, moving download URLs without a recorded version/checksum, an undersized host, or a dirty source checkout fails before assignment. |
| AWS request and bootstrap shape | Use structured AWS JSON/query output, fixed quoting, exact IDs, and no `eval` or human-table parsing. User data and instance tags are non-secret because EC2 and cloud-init expose them. Require encrypted EBS, delete-on-termination for created seats, IMDSv2, and a trial ownership tag plus role/seat tags on every issue-created resource. |
| Seat credential boundary | Generate one independent high-entropy passphrase per seat with a cryptographic source under an owner-only local directory. Publish the credential file with create-exclusive/no-follow/atomic semantics and mode `0600`. Set the Linux password through an encrypted operator channel and stdin-safe hashing/update path; plaintext or its hash must not appear in argv, exported environment, user data, SSM parameters/command history, logs, screenshots, Caddy config, or evidence. `/etc/shadow` is the expected verifier store. |
| Agent and lab credential boundary | Seat credentials, APTL `.env` service credentials, DCV certificates, operator SSH keys, and model-provider credentials are different secret classes. The runbook must name the tested model-auth mechanism and its teardown. Reuse the workbench broker/config boundary; never bake agent auth into the AMI, credential CSV, user data, shared home, or participant-readable MCP config. |
| DCV authentication and authorization | Pin `[security] authentication="system"` and the expected PAM service; create exactly one owner session for the matching `seatNN` user; deny collaboration/other-user access and unneeded DCV transfer/device features. Prove correct credentials succeed and missing/wrong credentials fail with the same generic external result. A reachable login page or an OS desktop login is not sufficient authentication evidence. |
| HTTP, WebSocket, and TLS boundary | Caddy accepts only the exact seat hostname, redirects HTTP, serves a valid public certificate, and proxies WebSocket traffic to the fixed loopback DCV endpoint. DCV accepts only the exact public Host and HTTPS Origin. Validate the loopback upstream certificate and bound timeouts; keep Caddy administration and auth/header logging non-public. |
| Host and cloud exposure | DCV web and QUIC listeners, Caddy, SSH, Docker publications, host firewall, security group, subnet/public-address state, and IPv4/IPv6 must agree. Externally probe allowed 80/443, operator-only 22 from both allowed and disallowed sources where feasible, and deny 8443, 3389, Docker, APTL API, victim, SOC, and management ports. Also inspect `ss` and Docker runtime publications so an accidental wildcard DCV bind cannot hide behind a passing proxy test. |
| APTL validation shapes | Load the strict guided profile and its referenced `aptl.json`, readiness suite, asset lock, scenario, and workbench profiles through the existing validators. Start through `aptl lab start`; preserve the canonical `.env` parser, placeholder checks, generated config, host-port resolver, startup diagnostics, and fixed profile. Do not pass hosted values around those parsers. |
| Readiness and evidence | Separately prove desktop/browser usability, installed agent version, exact MCP inventory, `kali_run_command` returning `uid=1000(kali)`, the bounded failed-SSH operation, and matching indexer and Wazuh rule-5710 results. Use `run_participant_mcp_smoke()` semantics; `tools/list`, HTTP 200, container health, or a visual desktop alone is not readiness. Store only versions, immutable identities, timestamps, stable check IDs, outcomes, counts, and redacted summaries. |
| Error and observability envelope | Disable shell tracing around secrets. Apply shared redaction before committed structured evidence and log stable operation labels rather than raw AWS, DCV, Caddy, PAM, agent, or MCP payloads. Do not commit full environment dumps, cloud-init output, `describe-*` responses, auth attempts, private addresses, process listings, session tokens, command lines, or raw backend results. |
| Reuse, replacement, and teardown | Classify each ledger entry as created or reused. Destructive commands resolve exact created IDs from the owner-only ledger, verify account/region/tags, delete in dependency order, wait for terminal state, and independently discover leftovers by trial tag. A reused host instead follows recorded compensating restore actions and a baseline diff. Final audit covers instances, volumes, snapshots/AMIs, ENIs, addresses, security groups/rules, DNS, IAM roles/profiles, key pairs, DCV/Caddy state, OS users/groups/passwords, agent auth, credential files, and temporary access material. |

## Extensibility Seam And Whole-Repository Scope

The only new seam is one parameterized operator seat input:

`(trial_id, seat_id, hostname, aws_profile, region, ami_id, instance_type,
subnet_id, security_group_id, operator_cidr, operator_key_ref,
root_volume_gib, host_recipe_id)`

The runbook derives `username == seat_id`, the fixed loopback DCV upstream, and
the common APTL port overrides from that input. It is not a persisted APTL DTO
or fleet database. The same admitted operation accepts `seat01` for proof and
later `seat01` through `seat12`; a future event may change domain, AMI,
instance type, subnet, volume, or operator source without editing the
canonical host recipe. Provider-neutral or dynamic-routing fields do not
belong at this seam.

Implementation has to reconcile these repository and runtime surfaces:

- issue #825, ADR-025, ADR-028, ADR-029, ADR-039, ADR-049, and issue #821;
- `docs/workshop/emergency-rollout.md`, installation/deployment guidance, and
  the guided workshop walkthrough;
- `participant-profiles/guided-purple-v1/`, `src/aptl/validation/`,
  `src/aptl/workbench/`, and their exact profile/agent/MCP tests;
- `src/aptl/core/{config,env,lab,lab_types,host_ports,endpoints,runstore}.py`,
  `src/aptl/utils/{pathsafe,redaction,logging,curl_safe}.py`, and MCP redaction
  parity;
- `docker-compose.yml`, `.mcp.json.example`, `.gitignore`,
  `.gitguardian.yaml`, secret-protection hooks, Vale/MkDocs, and the Ground
  Control host/range boundary declarations;
- AWS STS, EC2/AMI/EBS/ENI, VPC/subnet/routes, security groups, public
  addressing, Route 53, IAM/instance profiles, S3 license access, IMDS, and
  user data;
- Ubuntu PAM/accounts/groups/sudo/SSH, Docker and host firewall behavior,
  Caddy configuration/storage/logging/systemd, DCV configuration/PAM/session
  permissions/TLS/logging/systemd, and browser HTTPS/WebSocket behavior.

## Gotchas And Anti-Patterns

- Do not add an `AwsDeploymentBackend`, Terraform/CDK, fleet orchestrator,
  cloud config schema, shared ingress tier, or claim database for this proof.
- Do not use a shared gateway, Caddy Basic Auth, external-auth header, public
  8443, participant SSH/VPN/RDP, or one Linux account shared by seats.
- Do not call a developer host, EC2 instance, AMI, signed appliance payload,
  Docker image, and participant seat the same artifact.
- Do not add `seatNN`, hostname, password, model credential, AWS ID, or
  cloud-init state to the golden recipe. Those are per-launch state.
- Do not add the participant to sudo or the Docker group, expose the operator
  API/terminal, or treat per-VM isolation as permission to abandon least
  privilege inside the seat.
- Do not let Docker claim 443/8443, stop Caddy/DCV during lab start, or edit
  Compose to resolve the collision. Pin the existing host-port overrides in
  the common recipe and verify their runtime projection.
- Do not rely on UFW alone for Docker-published ports, on security-group
  intent without an external negative probe, or on IPv4 results when public
  IPv6 exists.
- Do not use `authentication="none"`, wildcard DCV host/origin regexes,
  default collaborative session permissions, public QUIC, a Caddy catch-all,
  an unverified upstream certificate, or request/header debug logging.
- Do not pass a passphrase or password hash to `useradd`, `usermod`,
  `chpasswd`, SSH, Caddy, or another tool in argv or an environment variable.
  Redaction after execution cannot remove OS-level exposure.
- Do not confuse the seat password with an APTL service password, model token,
  DCV TLS key, operator SSH key, or AWS credential.
- Do not copy the legacy seven-server workshop smoke list. Do not accept
  `tools/list`, TCP reachability, HTTP 200, or container health as proof of
  the real red/blue workflow.
- Do not use tags as the sole deletion selector, delete a reused host, omit
  waiters, assume delete-on-termination worked, or declare teardown complete
  before the independent resource and host-baseline audits pass.

## Non-Goals And Implementation Boundary

- This preflight does not create or modify AWS resources, the reused host,
  DNS, security groups, IAM, users, passwords, Caddy/DCV configuration, APTL
  runtime state, scripts, the runbook, or live evidence.
- It does not implement twelve seats, self-service assignment, shared ingress,
  autoscaling, regional failover, multi-provider abstraction, billing,
  participant account UI, or a new authentication service.
- It does not change RAES, `DeploymentBackend`, `AptlConfig`, participant
  profile/readiness schemas, MCP tool schemas, the workbench agent contract,
  exception hierarchies, runstore/evidence schemas, or inner lifecycle logic.
- It does not qualify ADR-049 payload parity unless the tested image passes
  that existing signed release and boundary contract.
- It does not authorize per-seat APTL configuration decisions, public lab or
  management services, participant Docker/sudo/SSH, mutable failed-seat
  repair, preservation of participant disks, or model credentials in the
  participant handout.
