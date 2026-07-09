# Emergency Workshop Rollout Runbook

This runbook covers the fallback path for an instructor-led workshop when
students cannot reliably run the lab on their own laptops. It is not the normal
APTL delivery model. The normal model remains:

```bash
pipx install aptl-labs
aptl lab init workshop
cd workshop
aptl lab start --yes
```

Use this guide when the workshop needs a short-lived hosted fleet with APTL,
Docker, Claude Code or another agent, and the MCP servers already working.

## Decision Gate

Use a hosted fallback only when at least one of these is true:

- student machines cannot install or run Docker in time;
- local operating-system variance is blocking the workshop;
- venue networking prevents package downloads or container image pulls;
- the workshop has already started and the facilitator needs a fast recovery
  path.

Do not use the fallback to avoid fixing the normal local install path. Any issue
found during a fallback should become a release or docs issue after the event.

## Capacity Model

Size the fleet from the instance vCPU count, not the instance count. For
example, 25 `m7i.2xlarge` hosts consume 200 Standard On-Demand vCPUs because
each host has 8 vCPUs. Keep quota headroom for canaries and replacement hosts.

Before launch, check:

```bash
aws service-quotas get-service-quota \
  --service-code ec2 \
  --quota-code L-1216C47A \
  --region "$AWS_REGION"
```

If a quota increase is needed, request the total desired vCPU quota, not just
the added capacity. Close the quota case after the event if it is no longer
needed.

## Golden Host

Build and validate one host before launching the class fleet.

Minimum host contract:

- supported student-like desktop access, usually RDP to an Ubuntu desktop;
- Docker installed and usable by the student account;
- `pipx`, Python, Node.js, and npm installed;
- `aptl-labs` installed from the intended release channel;
- the workshop lab initialized and started;
- Claude Code or the selected agent installed and authenticated;
- MCP servers built and registered from the workshop directory.

Do not validate on a materially different platform from the students. For
example, Windows Server or WSL does not prove the native Windows student path.

## Lab Contract

The hosted lab should start from the same workshop profile used in the local
walkthrough. Keep optional containers disabled unless the workshop needs them.
For the standard workshop, `reverse` stays disabled.

Expected workshop MCPs:

- `kali-ssh` for Kali command execution;
- `indexer` for raw Wazuh indexer queries;
- `wazuh` for SIEM query helpers;
- `network` for Suricata/network alert queries;
- `threatintel` for MISP;
- `cases` for TheHive;
- `soar` for Shuffle.

Do not register an MCP for a disabled service. A broken MCP entry is worse than
an absent one because it confuses students and agents.

## Readiness Proof

Every host needs machine-checked proof, not a visual spot check. At minimum,
validate:

```bash
aptl --version
aptl lab status
docker ps -a
node --version
npm --version
claude --version
claude mcp list
```

Then run direct MCP smoke tests through the Model Context Protocol client. The
smoke must call real backend operations, not only list tools:

- `kali_run_command` returns `uid=1000(kali)`;
- `indexer_query` returns HTTP 200;
- `wazuh_query_alerts` returns HTTP 200;
- `network_query_ids_alerts` returns HTTP 200;
- `threatintel_search_iocs` returns HTTP 200;
- `cases_list_cases` returns HTTP 200;
- `soar_list_workflows` returns HTTP 200.

Run one complete walkthrough through the agent and MCPs before students arrive.
The proof should include the MCP tool calls, the expected alert rule IDs, and
the source IPs seen by the SOC.

## Student Distribution

Do not publish a single public bundle that contains every credential. Prefer a
claim page:

- unguessable URL or neutral custom domain;
- workshop code shown in the room;
- one unused lab assignment per browser/session;
- generated RDP file for only the assigned host;
- displayed username and passphrase only for the assigned host;
- claim state stored server-side so assignments are not duplicated.

Email distribution is slower and less reliable unless SES production access is
already approved in the target region. SES sandbox mode can send only to
verified identities.

For a room display, use a QR code plus the workshop code. Avoid putting product
or security-sensitive terms in the public URL when a neutral name works.

## During The Event

Keep the fleet stable while students are using it:

- reuse hosts while debugging instead of rebuilding the fleet repeatedly;
- keep canary proof separate from student proof;
- watch quota and running instance count;
- avoid adding MCPs or services during the event unless a verified workaround
  requires it;
- if an issue does not block students, file it for later.

When fixing a host-level issue, make the remediation idempotent and run it
across the whole fleet. Then rerun the readiness proof across the whole fleet.

## Wind Down

When the event ends, remove both cost drivers and exposure surfaces:

```bash
aws ec2 terminate-instances --instance-ids "$INSTANCE_IDS"
aws lambda delete-function --function-name "$CLAIM_FUNCTION"
aws apigatewayv2 delete-api --api-id "$CLAIM_API"
aws dynamodb delete-table --table-name "$CLAIM_TABLE"
aws s3 rm "s3://$DISTRIBUTION_BUCKET" --recursive
aws s3api delete-bucket --bucket "$DISTRIBUTION_BUCKET"
```

Also check for and remove:

- AMIs and their EBS snapshots;
- available EBS volumes;
- event security groups and key pairs;
- pending ACM certificates;
- temporary IAM roles and instance profiles;
- open quota-increase support cases;
- local credential CSVs, RDP bundles, presigned URL files, and claim-page
  private state.

Keep non-secret proof artifacts and notes long enough to write issues and
post-event fixes.

## Lessons Learned

- Validate the exact user path. A Linux canary does not prove macOS or Windows,
  and Windows Server does not prove native student Windows.
- Cross-platform success means `aptl lab start` from the expected student shell
  with Docker installed, not a hand-curated container workaround.
- A connected MCP process is not enough. The proof must call a backend API or
  command for every MCP students will use.
- Persist service API keys in `.env` before registering SOC MCPs. TheHive keys
  can become stale; renewal must be safe and repeatable.
- Count Wazuh agents as a range, not a fixed number. Startup timing and enabled
  services can make 7 to 9 active agents normal.
- Quota requests are total desired quota values. Requesting the current value
  opens a support case without adding capacity.
- A claim page is safer than a public all-student RDP bundle and easier than
  email when SES is sandboxed.
- Teardown is part of the workshop. If AMIs, snapshots, buckets, and IAM roles
  are not in the checklist, they will be missed.
