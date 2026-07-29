# aptl-techvault-verifier

Semantic verification for the TechVault scenario running on the APTL backend.

This is deliberately **not** part of the `aptl-labs` distribution. Knowing that
`aptl-kali` is the attacker, that the defensive stack is Wazuh plus Suricata, and
what evidence proves a detection traversed it, is knowledge about one scenario on
one backend. APTL core must serve any scenario, so it holds none of it.

Installing this package is what gives the live gate a semantic verdict for
TechVault. Without it the gate reports `blocked` — not `passed`, and not
`failed` — because no verdict was possible.

Where a plugin like this ultimately lives (beside the range, in its own
repository, alongside the scenario pack) is not settled. It sits in this repo for
now so the seam can be exercised end to end, but it builds and installs as its
own distribution, which is what makes "core ships zero adapters" a checkable
claim rather than an assertion.
