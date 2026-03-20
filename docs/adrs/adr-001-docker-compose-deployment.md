# ADR-001: Migrate from AWS/Terraform to Local Docker Compose

## Status

accepted

## Date

2025-08-06

## Context

APTL v1.x deployed entirely to AWS using Terraform:

- **EC2 instances** for the SIEM (qRadar on a c5.4xlarge), Kali Linux (t3.micro), and a victim RHEL 9.6 machine
- **VPC** with public subnet, security groups, and bastion host SSH access
- **S3 + DynamoDB** for Terraform state management with UUID-based bucket names (to prevent enumeration)
- **Cost**: ~$280/month if left running continuously — the c5.4xlarge for qRadar alone was ~$250/month
- **qRadar Community Edition** required a 5GB ISO manual transfer, 1-2 hour installation, 5,000 EPS limit, and a 30-day trial license
- **Setup time**: Even with full Terraform automation, deploying from scratch took 30-60 minutes for infrastructure + 1-2 hours for qRadar installation
- **Network complexity**: VPC networking, security group rules, bastion host, inter-instance connectivity debugging

The barrier to entry was too high for a personal training lab. Every session meant either leaving expensive infrastructure running or spending an hour redeploying. The target audience — security practitioners wanting to practice purple team operations — would often abandon setup before reaching the first exercise.

Additionally, the AWS dependency created a hard coupling to a specific cloud provider and required AWS credentials, IAM permissions, and billing oversight that complicated sharing the project.

### Alternatives Considered

1. **Multi-cloud Terraform** (AWS, GCP, Azure modules): Would lower per-provider cost but not eliminate it. Increased maintenance burden across providers.
2. **Vagrant + VirtualBox**: Local deployment but heavyweight VMs. Slow provisioning, large disk footprint, no native container orchestration.
3. **Kubernetes (kind/minikube)**: Over-engineered for this scale. The lab needs ~5-15 containers, not a cluster orchestrator. Would add significant operational complexity.
4. **Docker Compose**: Native container orchestration, declarative configuration, instant startup, zero cloud costs, works offline.

## Decision

Replace the entire AWS/Terraform deployment model with Docker Compose running on the developer's local machine.

- All lab components run as Docker containers defined in a single `docker-compose.yml`
- No cloud infrastructure required — zero ongoing costs
- Single-command startup: `docker compose up` (later `aptl lab start`)
- Profiles enable selective deployment of container subsets (see [ADR-005](adr-005-docker-compose-profiles.md))
- Wazuh replaces qRadar as the SIEM (see [ADR-002](adr-002-wazuh-siem.md))
- Docker bridge networks replace VPC networking (see [ADR-006](adr-006-four-network-segmentation.md))

The initial v2.0.0 deployment included 5 containers: Wazuh Manager, Wazuh Indexer, Wazuh Dashboard, a Rocky Linux victim, and Kali Linux. This has since grown to 19 containers across 4 Docker networks.

### What Was Removed

- All Terraform infrastructure code (`infra/`, `vms/`)
- AWS-specific configuration (VPC, security groups, S3 state)
- qRadar Community Edition integration
- Bastion host SSH access pattern
- Cloud cost management overhead

### What Was Preserved

- The core purple team lab concept: SIEM + attacker + victim(s)
- MCP server integration for AI agent control
- SSH-based access to lab containers
- Documentation structure (migrated from VitePress to MkDocs)

## Consequences

### Positive

- **Zero cost**: No cloud billing. Lab can stay running indefinitely.
- **Instant startup**: Containers start in seconds vs. 30-60 minutes for Terraform + EC2
- **Offline capable**: Works without internet after initial image pulls
- **Reproducible**: `docker-compose.yml` is the complete deployment spec. No Terraform state, no cloud drift.
- **Lower barrier**: `git clone && aptl lab start` vs. AWS credentials + Terraform init + multi-step deployment
- **Portable**: Works on any machine with Docker — Linux, macOS, WSL2

### Negative

- **Single machine**: All containers compete for host resources. No horizontal scaling. ~20GB RAM needed for full stack.
- **No real network latency**: Docker bridge networking is near-zero latency, unlike real enterprise networks
- **No Windows containers**: Docker on Linux can't run Windows containers natively. Windows endpoints require a separate VM (see enterprise infrastructure docs).
- **Container escape risk**: Lab containers running on the developer's machine share the kernel. A container escape in a deliberately vulnerable container could affect the host. Mitigated by resource limits and non-root execution where possible.

### Risks

- Resource contention on machines with <16GB RAM. Mitigated by Docker Compose profiles allowing partial deployment.
- Docker Desktop licensing changes could affect commercial users (mitigated by supporting Docker Engine directly on Linux)
- Docker Compose v1 to v2 migration required updating all `docker-compose` commands to `docker compose` (space instead of hyphen)
