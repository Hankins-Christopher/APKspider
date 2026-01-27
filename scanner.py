import math
import os
from dataclasses import dataclass
from typing import List

from apkspider.patterns import PatternDefinition
from apkspider.report import Finding
from apkspider.scoring import score_from_base

SKIP_DIRS = {
    "res",
    "res/layout",
    "res/drawable",
    "res/font",
    "res/anim",
    "res/transition",
    "res/color",
    "res/mipmap",
    "build",
    "kotlin",
    "raw",
    "META-INF",
    "smali",
    "smali_classes2",
    "smali_classes3",
    "smali_classes4",
    "smali_classes5",
}

SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".so", ".ttf", ".otf"}
MAX_FILE_SIZE = 1024 * 512
SNIPPET_LENGTH = 120


@dataclass(frozen=True)
class ScanConfig:
    max_file_size: int = MAX_FILE_SIZE


def is_binary_data(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data:
        return True
    text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x7F)))
    nontext = data.translate(None, text_chars)
    return float(len(nontext)) / float(len(data)) > 0.30


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    entropy = 0.0
    length = len(value)
    for char in set(value):
        probability = value.count(char) / length
        entropy -= probability * (probability and math.log2(probability))
    return entropy


def redact_value(value: str) -> str:
    if len(value) <= 8:
        return "[redacted]"
    return f"{value[:4]}...{value[-4:]}"


def build_finding(pattern: PatternDefinition, match_value: str, file_path: str, detection_type: str) -> Finding:
    severity = score_from_base(pattern.severity, pattern.confidence)
    evidence = redact_value(match_value)
    return Finding(
        finding_id=pattern.pattern_id,
        title=pattern.title,
        description=pattern.description,
        evidence=evidence,
        impacted_files=[file_path],
        severity_score=severity.score,
        severity_label=severity.label,
        rationale=f"{pattern.rationale} {severity.rationale}",
        confidence=pattern.confidence,
        category=pattern.category,
        detection_type=detection_type,
        references=pattern.references,
        masvs=pattern.masvs,
        cvss_vector=pattern.cvss_vector,
    )


def scan_decompiled_dir(apk_dir: str, patterns: List[PatternDefinition], config: ScanConfig) -> List[Finding]:
    findings: List[Finding] = []
    path_patterns = [p for p in patterns if p.pattern_type == "path"]
    content_patterns = [p for p in patterns if p.pattern_type == "content"]

    for root, dirs, files in os.walk(apk_dir):
        rel_dir = os.path.relpath(root, apk_dir)
        if any(rel_dir.startswith(skip) for skip in SKIP_DIRS):
            continue
        for filename in files:
            rel_path = os.path.normpath(os.path.join(rel_dir, filename))
            if any(filename.endswith(ext) for ext in SKIP_EXTENSIONS):
                continue

            for pattern in path_patterns:
                if pattern.regex.search(rel_path):
                    findings.append(build_finding(pattern, rel_path, rel_path, "path_match"))

            full_path = os.path.join(root, filename)
            try:
                if os.path.getsize(full_path) > config.max_file_size:
                    continue
                with open(full_path, "rb") as handle:
                    data = handle.read()
                if is_binary_data(data):
                    continue
                content = data.decode("utf-8", errors="ignore")
            except OSError:
                continue

            for pattern in content_patterns:
                for match in pattern.regex.finditer(content):
                    match_value = match.group(0)
                    entropy = shannon_entropy(match_value)
                    detection = "content_match"
                    confidence = pattern.confidence
                    if pattern.entropy_threshold and entropy < pattern.entropy_threshold:
                        detection = "low_entropy_match"
                        confidence = "low"
                    evidence = match_value
                    if len(evidence) > SNIPPET_LENGTH:
                        evidence = evidence[:SNIPPET_LENGTH]
                    severity = score_from_base(pattern.severity, confidence)
                    findings.append(
                        Finding(
                            finding_id=pattern.pattern_id,
                            title=pattern.title,
                            description=pattern.description,
                            evidence=redact_value(evidence),
                            impacted_files=[rel_path],
                            severity_score=severity.score,
                            severity_label=severity.label,
                            rationale=f"{pattern.rationale} {severity.rationale}",
                            confidence=confidence,
                            category=pattern.category,
                            detection_type=detection,
                            references=pattern.references,
                            masvs=pattern.masvs,
                            cvss_vector=pattern.cvss_vector,
                        )
                    )
    return findings
