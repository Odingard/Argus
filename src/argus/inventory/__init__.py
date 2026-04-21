"""
argus.inventory — what models does this operator actually have access to?

Every ARGUS deployment ships with ``argus models`` which probes each
configured provider's keys, lists models the API believes are available,
and captures rate-limit / quota metadata where the provider exposes it.
Useful before starting a big engagement: confirm Opus is available,
confirm the Gemini quota is high enough, confirm no key has silently
been revoked.
"""
from argus.inventory.models import (
    ModelInfo, ProviderInventory, inventory_all, render_inventory_text,
)

__all__ = [
    "ModelInfo", "ProviderInventory", "inventory_all", "render_inventory_text",
]
