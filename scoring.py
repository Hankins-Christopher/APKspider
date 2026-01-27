from dataclasses import dataclass
from typing import Tuple

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
