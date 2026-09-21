"""Everything unique to the TechVault scenario that the APTL backend needs.

One plugin per scenario. A scenario asks the backend for things the backend
cannot know generically -- which components belong in which operator start
group, what proves the scenario's expectations held, which operations qualify a
participant -- and for TechVault all of it lives in this package, behind the
entry points APTL discovers it through.

This is an *adapter*, deliberately not portable. It names ``aptl-kali``,
``aptl-wazuh-manager``, APTL component addresses and APTL operator groups,
because that is what an answer key for one scenario on one backend is made of.
Handing it to another backend would be meaningless, which is why it belongs to
the backend rather than to the scenario author: an author cannot write the
adapter for a backend they have never seen, and many backends are private.

It ships inside the ``aptl-labs`` distribution and releases with it, so one
install gives an operator every extension surface the scenario owns. What stays
true is the separation, not the packaging: no module under ``aptl.`` holds
scenario knowledge, and a second scenario adds a package like this one rather
than editing the framework.

Nothing is imported here on purpose. Each entry point names its own submodule,
so loading one surface does not drag in the imports of the others -- which
matters because the framework requires entry-point loading to be side-effect
free, and because the surfaces do not share a dependency footprint.
"""

from __future__ import annotations

__version__ = "0.2.0"
