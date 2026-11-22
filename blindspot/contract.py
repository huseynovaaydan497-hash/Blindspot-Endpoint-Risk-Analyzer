"""
Blindspot shared data contract.

Every module talks to every other module ONLY through the shapes defined here
and documented in docs/API_CONTRACT.md.

Owner: D (integration). Change this file only through a reviewed pull request.
Adding a new OPTIONAL key is fine. Renaming or removing a key breaks other
people's code, so it is not allowed after H1.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "fixtures"

# The four independent risk signals. Each analyzer module produces one.
SIGNALS = ("permission", "code", "network", "reputation")

# Weight of each signal in the composite score. Must sum to 1.0.
SIGNAL_WEIGHTS = {"permission": 0.35, "code": 0.30, "network": 0.20, "reputation": 0.15}

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

# score >= 70 -> high, score >= 35 -> medium, otherwise low
LEVEL_THRESHOLDS = {"high": 70, "medium": 35}

# Recommendation per level, used by the report and the policy generator.
RECOMMENDATION = {"high": "block", "medium": "review", "low": "allow"}


def level_for(score: int) -> str:
    """Map a 0-100 score to a risk level."""
    if score >= LEVEL_THRESHOLDS["high"]:
        return "high"
    if score >= LEVEL_THRESHOLDS["medium"]:
        return "medium"
    return "low"


def severity_for_points(points: float) -> str:
    """Default severity for a finding worth `points` risk points."""
    if points >= 20:
        return "high"
    if points >= 10:
        return "medium"
    if points >= 4:
        return "low"
    return "info"


def finding(
    signal: str,
    severity: str,
    title: str,
    detail: str,
    evidence: str | None = None,
    points: float = 0,
) -> dict:
    """One explainable reason that contributes to a risk score.

    title    -- short label shown in lists ("Reads cookies on every site")
    detail   -- one plain-language sentence a non-expert can understand
    evidence -- what was observed: a permission name, or "file.js:12: <code>"
    points   -- how much this finding added to its signal score
    """
    if signal not in SIGNALS and signal != "score":
        raise ValueError(f"unknown signal {signal!r}")
    if severity not in SEVERITIES:
        raise ValueError(f"unknown severity {severity!r}")
    return {
        "signal": signal,
        "severity": severity,
        "title": title,
        "detail": detail,
        "evidence": evidence,
        "points": round(float(points), 1),
    }


def signal_result(score: float, findings: list[dict], available: bool = True, **extra) -> dict:
    """What every analyzer returns.

    score     -- 0..100 for this signal alone
    findings  -- list of finding() dicts
    available -- False when the signal could not be computed (no data, error);
                 unavailable signals are left out of the composite score
    extra     -- optional module-specific data (network adds `endpoints`)
    """
    return {
        "score": max(0, min(100, int(round(score)))),
        "findings": findings,
        "available": available,
        **extra,
    }


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
