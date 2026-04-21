"""
argus.drift — cross-run diffing for the two sinkholes (S1, S3).

  compare_runs        ghosts/new/changed chains + findings between two
                      scan result directories. Closes sinkhole S1
                      (Context Drift Fallacy).
  entitlement_drift   cumulative per-agent tool-invocation drift across
                      a series of runs. Closes sinkhole S3 (Privilege
                      Accumulation Trap).
"""
from argus.drift.compare import compare_runs, DriftReport, FindingDiff
from argus.drift.entitlements import (
    entitlement_drift, EntitlementSnapshot, EntitlementDriftReport,
)

__all__ = [
    "compare_runs", "DriftReport", "FindingDiff",
    "entitlement_drift", "EntitlementSnapshot", "EntitlementDriftReport",
]
