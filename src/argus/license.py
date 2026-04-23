"""
argus.license — feature-gate seam for PRO modules.

Today this is a permissive stub: `require()` always succeeds so every
contributor and CI runner gets full access with zero configuration.
The seam exists so that when the first paying PRO customer lands we
can swap in real verification in a single file — every PRO module
already calls `require("<feature>")` at import time, so the switch is
mechanical, not a refactor.

Resolution order when real verification ships:
    1. ARGUS_LICENSE=dev     → all features (developer escape hatch)
    2. Source checkout (.git present) → all features (running from a
       working tree is always trusted)
    3. ~/.argus/license.jwt  → signed token, verified against the
       owner public key shipped in the wheel
    4. None of the above     → core-only; PRO imports raise LicenseError

Until that lands, every call to `require()` returns None and every
`has()` returns True. The contract is stable; only the implementation
tightens.
"""
from __future__ import annotations

import os
from pathlib import Path


class LicenseError(RuntimeError):
    """Raised when a PRO feature is imported without a valid license.

    Today unreachable — the stub permits everything. Kept in the public
    surface so PRO modules can import and raise it without a future
    circular-import risk."""


def _dev_escape_hatch() -> bool:
    return os.environ.get("ARGUS_LICENSE", "").lower() in {
        "dev", "owner", "internal",
    }


def _source_checkout() -> bool:
    # `src/argus/license.py` → project root is parents[2]
    root = Path(__file__).resolve().parents[2]
    return (root / ".git").is_dir()


def has(feature: str) -> bool:
    """True if `feature` is currently licensed for use.

    Stub: always True. Real impl will inspect env + source-checkout +
    signed token."""
    del feature
    return True


def require(feature: str) -> None:
    """Raise LicenseError if `feature` is not licensed. Stub: no-op.

    Call this at the top of every PRO module:

        from argus.license import require
        require("mcts")
    """
    if has(feature):
        return
    raise LicenseError(
        f"ARGUS feature '{feature}' requires a PRO license. "
        f"See https://github.com/Odingard/argus-core#pro for details."
    )


def subject() -> str:
    """One-line human-readable description of the active license,
    used by `argus --version` and the CLI banner."""
    if _dev_escape_hatch():
        return "dev (ARGUS_LICENSE env)"
    if _source_checkout():
        return "source-checkout (unrestricted)"
    return "core (LITE tier)"
