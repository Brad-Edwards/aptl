"""ACES experiment admission input layer (ADR-047, EXP-002 / issue #438).

Deliberately empty. Downstream code imports the concrete submodules
directly (``aptl.core.experiment.errors``, ``.policy``, ``.resolver``,
``.spec_loading``, ...) rather than re-exporting everything from this
package's ``__init__``, so parallel admission-slice work lands in its own
module without every stage fighting over one shared export surface.
"""

from __future__ import annotations
