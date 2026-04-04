# SDL Limitations & Future Work

## Known Expressiveness Gaps

These are things the SDL cannot currently express, identified through stress-testing against 19 real-world scenarios from 8 platforms.

### Deployment-Layer Gaps (by design — belong in provider bindings)

These are intentionally excluded from the specification layer:

- **Port mappings** (host:container exposure) — deployment detail
- **Volume mounts** — deployment detail
- **Linux capabilities** (NET_RAW, SYS_ADMIN) — deployment detail
- **Security options** (seccomp, cgroup) — deployment detail
- **Docker Compose profiles** — deployment-specific grouping
- **Image build contexts** (Dockerfile paths) — deployment detail
- **Container entrypoints/commands** — deployment detail
- **Extra hosts** (/etc/hosts overrides) — deployment detail
- **Ulimits** (nofile, memlock) — deployment detail

These remain outside the language itself and are addressed by provider bindings
and runtime deployment adapters rather than by the SDL surface.

### Specification-Layer Gaps (future SDL work)

These are things that *should* be expressible in the SDL but aren't yet:

| Gap | Description | Candidate Precedent |
|-----|-------------|-------------------|
| **Hosted registry operations / ecosystem distribution** | OCI-backed module resolution, lockfiles, trust policy, and publishable image-layout packaging now exist, but operating a shared registry service, signer distribution, and ecosystem-wide discovery policy are still future work | Terraform registry, OCI artifact delivery |
| **Manual compensation APIs / advanced rollback patterns** | SDL workflows now support explicit automatic compensation targets, reverse-completion rollback ordering, and cancel/timeout/failure compensation observation, but not manual rollback triggers, nested compensation-of-compensation, or richer exception-style recovery surfaces | CACAO v2.0 workflow types, saga compensation patterns |
| **Temporal operators** | STIX-style FOLLOWEDBY/WITHIN for time-ordered event assertions | STIX Patterning Language |
| **Full solver-backed verification** | Global proof-style verification that attack paths are reachable and defenses are consistent is still future work; today the repo adopts lightweight semantic modeling, invariants, typed contracts, and selective property/state-machine methods instead | VSDL SMT solver, CRACK Datalog |
| **Agent framework bindings** | Gymnasium observation/action space definitions, reward function code | CybORG Gymnasium interface |
| **User behavior profiles** | Normal user activity patterns (browsing, email, file access schedules) | CybORG Green agents |
| **Multi-tenancy** | Multiple independent exercises sharing infrastructure | Locked Shields team-per-subnet model |

### Variable Resolution

Variables (`${var_name}`) are stored as literal strings in the model. They are **not** resolved at parse time. This means:

- The validator can confirm that a full-value `${var}` reference has a matching variable definition
- Cross-reference rules that depend on a placeholder's final concrete value are deferred to the repo-owned instantiation phase
- Selected leaf enum-backed property fields are parameterizable, but discriminant/schema-shaping enums and user-defined mapping keys are still concrete
- Type checking of substituted runtime values happens during APTL instantiation, before compilation/runtime planning

This is a deliberate design choice (matching CACAO's model), but substitution
semantics are now owned by the repo rather than left to backend-specific
interpretation.

## What Has Been Validated

The SDL has been tested against 19 scenarios from 8 platforms:

| # | Scenario | Source | Nodes | Services | Vulns |
|---|----------|--------|-------|----------|-------|
| 1 | OCR Full Exercise | OCR test suite | 3 | - | 1 |
| 2 | CybORG CAGE-1 | CAGE Challenge 1 | 7 | - | 2 |
| 3 | CybORG CAGE-2 (13-host) | CAGE Challenge 2 | 16 | - | 5 |
| 4 | CALDERA Ransack | CALDERA adversary | 0 | - | 0 |
| 5 | Atomic Red Team T1003 | Atomic tests | 0 | - | 0 |
| 6 | CyRIS DMZ | CyRIS | 7 | 3 | 2 |
| 7 | KYPO CTF | KYPO | 3 | - | 3 |
| 8 | HTB Machine | Hack The Box | 2 | 3 | 2 |
| 9 | Enterprise AD | Multi-domain lab | 10 | - | 6 |
| 10 | Cloud Hybrid | AWS VPC + on-prem | 9 | - | 3 |
| 11 | Exchange + data | APTL extended | 5 | 3 | 1 |
| 12 | CybORG with agents | CAGE-2 + agents | 9 | - | 1 |
| 13 | AD trust + federation | Multi-domain + vars | 6 | - | 2 |
| 14 | Incalmo Equifax | MHBench | 6 | 7 | 2 |
| 15 | NICE Challenge 17 | NICE/NIST | 6 | 9 | 3 |
| 16 | CCDC 2007 | Competition packet | 5 | 11 | 0 |
| 17 | HTB Offshore-style | ProLab | 6 | 11 | 6 |
| 18 | Metasploitable 2 | Classic lab | 2 | 23 | 11 |
| 19 | Locked Shields IT/OT | NATO exercise | 7 | 13 | 0 |

Additionally, the real APTL lab topology (28 nodes, 4 networks, 17 health checks, 17 vulnerabilities) has been described in SDL and validated.

Property-based fuzz testing (Hypothesis) has run 1,050+ random inputs through the parser with zero unhandled crashes.
