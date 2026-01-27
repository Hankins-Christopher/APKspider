import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

DEFAULT_PATTERN_PATH = Path(__file__).resolve().parent / "data" / "sensitive_patterns_v1.json"


@dataclass(frozen=True)
class PatternDefinition:
    pattern_id: str
    title: str
    pattern_type: str
    regex: re.Pattern
    description: str
    severity: str
    confidence: str
    category: str
    rationale: str
    references: List[str]
    masvs: List[str]
    cvss_vector: str
    entropy_threshold: Optional[float] = None


def load_patterns(path: Optional[Path] = None) -> List[PatternDefinition]:
    pattern_path = Path(path) if path else DEFAULT_PATTERN_PATH
    data = json.loads(pattern_path.read_text(encoding="utf-8"))
    patterns: List[PatternDefinition] = []
    for entry in data.get("patterns", []):
        patterns.append(
            PatternDefinition(
                pattern_id=entry["id"],
                title=entry["title"],
                pattern_type=entry["type"],
                regex=re.compile(entry["regex"]),
                description=entry["description"],
                severity=entry["severity"],
                confidence=entry["confidence"],
                category=entry["category"],
                rationale=entry["rationale"],
                references=entry.get("references", []),
                masvs=entry.get("masvs", []),
                cvss_vector=entry.get("cvss_vector", ""),
                entropy_threshold=entry.get("entropy_threshold"),
            )
        )
    return patterns


def load_pattern_metadata(path: Optional[Path] = None) -> dict:
    pattern_path = Path(path) if path else DEFAULT_PATTERN_PATH
    return json.loads(pattern_path.read_text(encoding="utf-8"))
