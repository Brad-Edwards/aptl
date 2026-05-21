# ACES Inventory Methodology Assurance Report

This report reviews the APTL #353 asset-inventory methodology and tooling for
defensibility under DevOps/security practice, supply-chain evidence practice,
reproducible-research expectations, and verification/validation thinking. It is
not a final TechVault asset specification. It exists to keep the methodology
itself from drifting while #330, #331, #332, and later ACES/APTL gap issues do
the full encoding work.

## Current Position

The methodology is defensible as a capture-to-specification workflow if it is
used with the ledger gates now in the repo:

- `mapping-ledger.yaml` is the accountability artifact for every captured fact.
- `aptl aces-inventory validate <asset-dir>` validates the ledger schema,
  evidence references, and mapping disposition requirements.
- `aptl aces-inventory gaps <asset-dir>` emits the actionable gap list later
  issues must consume or fix.
- `aptl aces-inventory schema` emits the current JSON Schema generated from the
  Pydantic ledger model.

The methodology is not yet sufficient to claim final equivalence between a
future ACES encoding and a realized APTL deployment. That requires the planned
correspondence checks in the ledger to become implemented checks after the
encoding exists.

## Practice Alignment

| Concern | Methodology position | Basis |
| --- | --- | --- |
| Configuration management | Captures realized runtime configuration, evidence paths, mutable-tag limits, redactions, and disposition of each fact. | NIST SP 800-128 treats security-focused configuration management as an explicit lifecycle concern for establishing and monitoring configuration state. |
| Container security | Captures immutable image digest, runtime configuration, mounts, socket exposure, package inventory, and vulnerability scan state. | NIST SP 800-190 identifies container images, registries, orchestrators, runtime isolation, and host interactions as security-relevant surfaces. |
| SBOM practice | Captures CycloneDX SBOM and package inventory; accepts SPDX/CycloneDX as standards-backed formats. | NTIA/CISA SBOM guidance defines minimum SBOM transparency expectations; CycloneDX and SPDX are standard SBOM formats. |
| Provenance and attestations | Captures registry-visible Docker/OCI attestation manifests when available; requires first-party custom builds to prefer build-time SBOM/provenance attestations. | Docker Build attestations, SLSA provenance, and in-toto provide established supply-chain attestation patterns. |
| Evidence provenance | Separates captured facts, evidence paths, tool output, and provenance metadata. | W3C PROV distinguishes entities, activities, and agents for auditable provenance. |
| Reproducible research | Preserves enough artifact, tool, environment, and parameter evidence to rerun and challenge the claim. | Peng, Goodman et al., and ACM artifact-review guidance frame reproducibility as artifact-backed evaluation, not narrative alone. |
| Cyber-range scenario rigor | Treats scenario assets, services, topology, and evidence as explicit artifacts rather than backend lore. | Cyber-range literature emphasizes scenario definition, infrastructure, tooling, monitoring, and evaluation as separable concerns. |
| V&V / correspondence | Adds planned correspondence checks tying future ACES surfaces to realized evidence. | NASA model/simulation assurance guidance and IEEE-style V&V practice emphasize evidence that the model satisfies requirements and corresponds to intended use. |

## Improvements Made In This Pass

The prior proof captured useful evidence but left several methodology risks too
implicit. This pass closes the visible problems now:

- The ledger is now schema-governed by Pydantic models, with a schema CLI.
- The ledger now has an explicit provenance block, including attestation status,
  predicate types, evidence paths, verification status, and limits.
- The shuffle-backend proof now captures Docker Buildx image-index evidence and
  the amd64 attestation manifest showing an in-toto layer with SLSA provenance
  predicate type.
- The ledger now has explicit correspondence-check records. They are planned,
  not implemented, because #353 is methodology/tooling and not final ACES
  encoding.
- The docs state scanner limits, attestation-verification limits, and
  correspondence limits directly.

## Remaining Limits

These limits are acceptable for the #353 methodology/tooling scope, but later
issues must not silently carry them into final claims:

- The shuffle-backend capture came from an already-running local lab, not a
  clean `aptl lab stop -v && aptl lab start` capture.
- Registry-visible upstream attestations were captured but not
  cryptographically verified for signature, transparency-log inclusion, or
  builder identity.
- The Trivy SBOM and vulnerability outputs are scanner state tied to tool,
  database, advisory, and capture time. They are not permanent ground truth.
- The ledger proves mapping accountability, not semantic completeness of ACES.
  ACES #354 remains a blocker for typed runtime configuration surfaces.
- Correspondence checks are planned. Final encoding issues must implement them
  by comparing ACES/source-package content against fresh realized evidence.

## Required Bar For Later Asset Issues

Each follow-on asset issue should meet this minimum:

1. Capture evidence from a clean steady-state lab unless the issue explicitly
   records why that is impossible.
2. Use digest-pinned image references; mutable tags are never sufficient.
3. Check for registry-visible attestations on upstream images.
4. For custom builds, emit or capture build-time SBOM/provenance attestations
   using Docker Buildx `--sbom` and `--provenance` or equivalent in-toto/SLSA
   tooling.
5. Validate the mapping ledger with `aptl aces-inventory validate`.
6. Run `aptl aces-inventory gaps` and file/link gap issues before encoding
   unsupported facts through semantically wrong ACES fields.
7. Add or update correspondence checks so the future ACES encoding can be
   verified against realized evidence.

## References

- NIST SP 800-128, *Guide for Security-Focused Configuration Management of
  Information Systems*. https://csrc.nist.gov/pubs/sp/800/128/upd1/final
- NIST SP 800-190, *Application Container Security Guide*.
  https://csrc.nist.gov/pubs/sp/800/190/final
- NTIA, *The Minimum Elements For a Software Bill of Materials*.
  https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom
- CISA, *Software Bill of Materials*. https://www.cisa.gov/sbom
- CycloneDX specification overview. https://cyclonedx.org/specification/overview/
- SPDX specifications. https://spdx.dev/use/specifications/
- Docker Build attestations. https://docs.docker.com/build/metadata/attestations/
- SLSA specification v1.2. https://slsa.dev/spec/v1.2/
- in-toto project. https://in-toto.io/
- W3C PROV-DM. https://www.w3.org/TR/prov-dm/
- ACM Artifact Review and Badging. https://www.acm.org/publications/policies/artifact-review-and-badging-current
- Peng, "Reproducible Research in Computational Science", *Science*, 2011.
  https://doi.org/10.1126/science.1213847
- Goodman, Fanelli, and Ioannidis, "What does research reproducibility mean?",
  *Science Translational Medicine*, 2016.
  https://doi.org/10.1126/scitranslmed.aaf5027
- Boettiger, "An introduction to Docker for reproducible research",
  *ACM SIGOPS Operating Systems Review*, 2015.
  https://doi.org/10.1145/2723872.2723882
- Yamin, Katt, and Gkioulos, "Cyber ranges and security testbeds: Scenarios,
  functions, tools and architecture", *Computers & Security*, 2020.
  https://doi.org/10.1016/j.cose.2019.101636
- NASA-STD-7009, *Standard for Models and Simulations*.
  https://standards.nasa.gov/standard/nasa/nasa-std-7009
