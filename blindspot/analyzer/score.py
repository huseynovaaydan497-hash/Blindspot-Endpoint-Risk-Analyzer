"""
Risk rating -- hackathon requirement 3 ("Calculate a basic risk score per extension").

Owner: B

Method: OWASP Risk Rating Methodology (Risk = Likelihood x Impact), customised as
OWASP's own "Step 6: Customizing your risk rating model" allows. Full write-up with
sources: docs/METHODOLOGY.md.

Public interface:
    rate(signals, exposure_count=0) -> rating dict
    combine(signals, known_good=False, exposure_count=0) -> (score, level, extra_findings, rating)
    SEVERITY_MATRIX, band(value)

How it works

1. Every analyzer produces a 0-100 signal. Each is rescaled to OWASP's 0-9 factor scale.

   Likelihood factors (how likely is it that this extension is, or becomes, hostile?)
     code        malicious-code indicators: eval, obfuscation, cookie dumping ...
     network     talks to servers nobody recognises, raw IPs, plain HTTP
     reputation  supply-chain trust: removed from the store, abandoned, unknown publisher

   Impact factors (what could it do to us if it were hostile?)
     technical   what the permissions let it read and change (permission signal)
     business    how many of OUR crown-jewel systems it can reach (exposure)

   A factor is never below 8 when its signal has a critical finding.

2. Each side is combined as 0.6 * strongest factor + 0.4 * average of the factors.
   OWASP's default is a plain average; Step 6 allows weighting. A plain average lets
   one severe factor (for example "removed from the store for malware") disappear
   among clean ones, so the strongest factor keeps 60% of the weight.
   If no likelihood factor could be measured, likelihood is set to 4.5 (medium):
   unknown is not the same as safe.

3. Likelihood and impact are each put into OWASP's bands: 0-<3 LOW, 3-<6 MEDIUM,
   6-9 HIGH, and OWASP's severity matrix gives Note / Low / Medium / High / Critical.

4. The 0-100 score is that severity band, refined by L x I inside the band, so the
   band boundaries are the same as the levels used everywhere else:
       Critical 85-100, High 70-84   -> level "high"   -> block
       Medium   35-69                -> level "medium" -> review
       Low      10-34, Note 0-9      -> level "low"    -> allow
"""
from __future__ import annotations

from blindspot.contract import finding, level_for

PEAK_SHARE = 0.6
UNKNOWN_LIKELIHOOD = 4.5
KNOWN_GOOD_CAP = 34  # an organisation-approved extension is never above "low"

LIKELIHOOD_FACTORS = ("code", "network", "reputation")
IMPACT_FACTORS = ("technical", "business")

# OWASP Risk Rating Methodology, step 4: overall risk severity.
#                   likelihood:  LOW       MEDIUM    HIGH
SEVERITY_MATRIX = {
    "HIGH":   {"LOW": "Medium", "MEDIUM": "High",   "HIGH": "Critical"},
    "MEDIUM": {"LOW": "Low",    "MEDIUM": "Medium", "HIGH": "High"},
    "LOW":    {"LOW": "Note",   "MEDIUM": "Low",    "HIGH": "Medium"},
}

# score range of each severity (inclusive)
SEVERITY_BANDS = {
    "Critical": (85, 100), "High": (70, 84), "Medium": (35, 69), "Low": (10, 34), "Note": (0, 9),
}


def band(value: float) -> str:
    """OWASP likelihood / impact levels: 0 to <3 LOW, 3 to <6 MEDIUM, 6 to 9 HIGH."""
    if value < 3:
        return "LOW"
    if value < 6:
        return "MEDIUM"
    return "HIGH"


# A factor can never be lower than its worst confirmed finding. A single critical
# fact such as "removed from the Chrome Web Store" means likelihood is high, however
# few other points the signal collected.
SEVERITY_FLOOR = {"critical": 8.0}


def _to_factor(signal: dict) -> float:
    value = max(0.0, min(100.0, float(signal.get("score", 0)))) * 9 / 100
    for f in signal.get("findings", []):
        value = max(value, SEVERITY_FLOOR.get(f.get("severity"), 0.0))
    return round(value, 1)


def _business(exposure_count: int) -> float:
    """Reaching one crown-jewel system is already a high business impact."""
    return {0: 0.0, 1: 6.0, 2: 7.0, 3: 8.0}.get(exposure_count, 9.0)


def _combine(values: list[float]) -> float:
    if not values:
        return 0.0
    return round(PEAK_SHARE * max(values) + (1 - PEAK_SHARE) * sum(values) / len(values), 2)


def rate(signals: dict, exposure_count: int = 0) -> dict:
    available = {n: s for n, s in signals.items() if s.get("available", True)}

    likelihood_factors = {n: _to_factor(available[n]) for n in LIKELIHOOD_FACTORS if n in available}
    impact_factors = {"business": _business(exposure_count)}
    if "permission" in available:
        impact_factors["technical"] = _to_factor(available["permission"])

    likelihood = _combine(list(likelihood_factors.values())) if likelihood_factors else UNKNOWN_LIKELIHOOD
    impact = _combine(list(impact_factors.values()))
    l_band, i_band = band(likelihood), band(impact)
    severity = SEVERITY_MATRIX[i_band][l_band]
    low, high = SEVERITY_BANDS[severity]
    score = round(low + (high - low) * (likelihood * impact) / 81)

    return {
        "method": "OWASP Risk Rating Methodology (Likelihood x Impact)",
        "likelihood": round(likelihood, 1), "likelihood_level": l_band,
        "impact": round(impact, 1), "impact_level": i_band,
        "severity": severity, "score": score,
        "factors": {
            "likelihood": likelihood_factors,
            "impact": impact_factors,
        },
        "likelihood_unknown": not likelihood_factors,
    }


def combine(signals: dict, known_good: bool = False,
            exposure_count: int = 0) -> tuple[int, str, list[dict], dict]:
    rating = rate(signals, exposure_count)
    score = rating["score"]
    extra: list[dict] = []
    rating["raw_score"] = score
    rating["raw_severity"] = rating["severity"]

    if known_good and score > KNOWN_GOOD_CAP:
        extra.append(
            finding("score", "info", "On the organisation's approved list",
                    f"Rated {rating['severity']} ({score}), capped to {KNOWN_GOOD_CAP} because this extension "
                    "ID is approved in fixtures/known_good.json. Guard still checks every new version.",
                    evidence="known_good.json", points=0)
        )
        score = KNOWN_GOOD_CAP
        rating["severity"] = "Low"
        rating["capped"] = True

    score = max(0, min(100, score))
    rating["score"] = score
    return score, level_for(score), extra, rating
