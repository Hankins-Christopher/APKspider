from dataclasses import dataclass
from typing import Dict, Tuple

SEVERITY_SCORES = {
    "info": 0.0,
    "low": 3.1,
    "medium": 6.5,
    "high": 8.8,
    "critical": 9.8,
}

SEVERITY_LABELS = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "info"),
]

CONFIDENCE_MODIFIERS = {
    "high": 1.0,
    "medium": 0.9,
    "low": 0.7,
}


@dataclass(frozen=True)
class SeverityResult:
    score: float
    label: str
    rationale: str


@dataclass(frozen=True)
class RiskResult:
    score: float
    label: str
    breakdown: Dict[str, float]


def normalize_severity_label(label: str) -> str:
    lowered = label.strip().lower()
    return lowered if lowered in SEVERITY_SCORES else "medium"


def score_from_base(base_label: str, confidence: str) -> SeverityResult:
    base = SEVERITY_SCORES[normalize_severity_label(base_label)]
    modifier = CONFIDENCE_MODIFIERS.get(confidence.lower(), 0.85)
    score = round(base * modifier, 1)
    label = label_from_score(score)
    rationale = (
        f"Base severity '{base_label}' adjusted by confidence '{confidence}' using "
        f"modifier {modifier} to produce score {score}."
    )
    return SeverityResult(score=score, label=label, rationale=rationale)


def label_from_score(score: float) -> str:
    for threshold, label in SEVERITY_LABELS:
        if score >= threshold:
            return label
    return "info"


def cvss_summary(score: float, vector: str) -> Tuple[str, str]:
    label = label_from_score(score)
    summary = f"CVSS-like base score {score} ({label})."
    if vector:
        summary = f"CVSS v3.1 vector {vector} with base score {score} ({label})."
    return summary, label


def score_with_modifiers(
    severity_label: str,
    confidence: str,
    category: str,
    title: str,
    detection_type: str,
    references: list,
) -> RiskResult:
    normalized = normalize_severity_label(severity_label)
    base = SEVERITY_SCORES[normalized]
    confidence_modifier = CONFIDENCE_MODIFIERS.get(confidence.lower(), 0.85)
    score = base * confidence_modifier

    reachability_modifier = 0.0
    title_lower = title.lower()
    category_lower = category.lower()
    if any(keyword in title_lower for keyword in ["exported", "intent", "deeplink", "url scheme"]):
        reachability_modifier += 0.7
    if "network" in category_lower or "cleartext" in title_lower:
        reachability_modifier += 0.5

    credential_modifier = 0.0
    if any(keyword in title_lower for keyword in ["secret", "token", "api key", "credential"]):
        credential_modifier += 0.9
    if "secrets" in category_lower:
        credential_modifier += 0.6

    known_vuln_modifier = 0.0
    if any("cve" in str(ref).lower() for ref in references):
        known_vuln_modifier += 1.0
    if "vulnerable" in title_lower:
        known_vuln_modifier += 0.5

    detection_modifier = 0.0
    if detection_type == "low_entropy_match":
        detection_modifier -= 0.3

    score += reachability_modifier + credential_modifier + known_vuln_modifier + detection_modifier
    score = max(0.0, min(10.0, round(score, 2)))
    label = label_from_score(score)
    breakdown = {
        "base": round(base, 2),
        "confidence_modifier": round(confidence_modifier, 2),
        "reachability_modifier": round(reachability_modifier, 2),
        "credential_modifier": round(credential_modifier, 2),
        "known_vuln_modifier": round(known_vuln_modifier, 2),
        "detection_modifier": round(detection_modifier, 2),
        "final_score": score,
    }
    return RiskResult(score=score, label=label, breakdown=breakdown)
