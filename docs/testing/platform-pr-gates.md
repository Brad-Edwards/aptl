# Platform pull-request gates

Pull requests to `dev` require the existing **Pre-commit hooks**, **Python
tests + coverage**, **MCP TypeScript tests + coverage**, **Dependency
vulnerability scan**, and **Clean-install lab boot and teardown (DEP-008)**
contexts. Other established required quality and governance checks remain in
the branch rule. The exact context names are recorded in
`.github/branch-protection-baseline.json`; the live GitHub branch settings are
the enforcement authority.

The dependency job fails on known Python findings in the generated CLI/runtime,
API/web, and CI/build exports and on high or critical production dependency
findings in the web and all MCP package locks. It also fails when a lock,
install, or scanner fails. Trivy filesystem, image, and IaC scans and the OSV
scan remain advisory because they cover mixed platform and intentionally
vulnerable target assets. ADR-026 records the boundary and the format for any
temporary platform exception. There are currently no such exceptions.

The clean-install job builds a wheel, installs it in an empty virtual
environment, materializes a fresh project, and starts only the product-neutral
`materialization-envelope.sdl.yaml` scenario from APTL's owned
[lab fixture pack](lab-fixture-pack.md). It checks native effects in the
project's running container, stops the lab with volumes, and proves that the
effective workspace project has no remaining containers, networks, or volumes.

The scenario carries one causal realization chain, so none of those checks can
pass on a declaration alone: inline content moves the SSH daemon off its
package default port, the declared service unit starts it, the declared
listener binds the moved port, and that port is published on an exact loopback
host binding. `scripts/ci/assert_boot_realization.py` reads the placed bytes
inside the container, queries the service manager for the unit's enabled,
active and result state, observes the live listener from outside the
container's trust boundary, requires the exact published-port tuple and no
wider one, opens a connection to it, and parses the persisted workflow with
the RAES execution-state contract. `docs/testing/boot-realization-coverage.md`
maps every concern APTL's realization envelope advertises to the tests that
hold it, and names the concerns this small boot deliberately does not claim.

These checks support the **generic installed-wheel materialization and lab
lifecycle profile on a GitHub-hosted Ubuntu runner with local Docker**. They do
not qualify the full TechVault or LilRAE journey. Those qualifications are
tracked in APTL #870 and #685, and OpenRAE/lilrae #4, #9, and #10.
