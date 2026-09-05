# Review Evidence

These are point-in-time review artifacts for APTL commit
`f35f86ee3bcc41f0b918fd209a944bf91e83f659`, captured on 2026-09-05.
Files labelled `final` record verification after incorporating upstream
`65390508db54d118b4dd685db742f3a282b4f366` and the review documents.

| Artifact | Meaning |
| --- | --- |
| [Pre-commit log](precommit-baseline.txt) | All configured baseline hooks passed; quiet hooks do not expose test counts |
| [Static gate log](static-gate.txt) | Two static/no-start tests passed; no live range claim |
| [Process probe](process-probes.py) / [results](process-results.json) | Real harmless subprocess tests showing input deadline overrun and descendant survival |
| [Boundary probe](boundary-probes.py) / [results](boundary-results.json) | Real Python methods against a fake daemon and temporary synthetic env/files |
| [Dev protection snapshot](dev-protection.json) | Required status contexts and review configuration read through GitHub API |
| [Final pre-commit log](precommit-final.txt) | Configured hooks on the updated branch; verbose output records test counts and suite skips |
| [Final static gate](static-gate-final.txt) | 2 passed in 58.30 seconds; still no-start evidence |
| [Final process results](process-final.json) / [boundary results](boundary-final.json) | Same defects reproduced at the updated source baseline; 0.2-second input deadline returned success after 2.022 seconds |
| [Upstream changed paths](upstream-959-files.tsv) | Explicit delta from the initial tracked-file inventory |

Run the probes from the baseline checkout with its installed development
environment:

```console
.venv/bin/python docs/reviews/962-lilrae-readiness/evidence/process-probes.py
.venv/bin/python docs/reviews/962-lilrae-readiness/evidence/boundary-probes.py
```

The process probe launches local Python children and explicitly kills the
synthetic surviving child. The boundary probe uses mocked daemon calls,
temporary files and an isolated synthetic environment. It does not launch
Docker, read real credentials, or change a user file. Results deliberately
describe the baseline defects rather than asserting that they are fixed.

No range start/stop, firewall modification, volume reset, model call, cloud
deployment or release was performed. Future qualification must run on a clean
supported host/isolated daemon using exact acquired artifacts.

The strict MkDocs build and direct Vale check also passed. The documentation
build emitted revision-date plugin warnings, including an existing ADR; these
are timestamp metadata warnings rather than broken document links. The Python
suite emitted a Starlette/httpx deprecation warning. Neither changes the
qualification limits above.

The completed run passed 4,578 Python tests, 462 common MCP tests, 216 red MCP
tests and 238 frontend tests. Python reported 94 skips: live smoke tests were
not enabled, two cases require Windows semantics, and one supply chain test
skips because its fixture was removed or relocated. #969 must reconcile that
missing-fixture skip and make release qualification skips explicit.

An earlier final-check attempt passed 4,578 Python tests with 94 skips, but
pre-commit stopped because the review documents changed during its run. The
recorded final run was repeated after the files settled. Passing tests do not
resolve the reproduced defects. Suite selection/skips are visible in the log;
live range and provider qualification were not exercised.
