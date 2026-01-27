import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import List


@dataclass
class Finding:
    finding_id: str
    title: str
    description: str
    evidence: str
    impacted_files: List[str]
    severity_score: float
    severity_label: str
    rationale: str
    confidence: str
    category: str
    detection_type: str
    references: List[str] = field(default_factory=list)
    masvs: List[str] = field(default_factory=list)
    cvss_vector: str = ""


@dataclass
class Report:
    tool: str
    tool_version: str
    target: str
    generated_at: str
    findings: List[Finding]
    pattern_version: str
    pattern_sources: List[str]

    def to_json(self) -> str:
        payload = {
            "metadata": {
                "tool": self.tool,
                "tool_version": self.tool_version,
                "target": self.target,
                "generated_at": self.generated_at,
                "pattern_version": self.pattern_version,
                "pattern_sources": self.pattern_sources,
            },
            "findings": [asdict(finding) for finding in self.findings],
        }
        return json.dumps(payload, indent=2)


def build_report(tool: str, tool_version: str, target: str, findings: List[Finding], pattern_meta: dict) -> Report:
    return Report(
        tool=tool,
        tool_version=tool_version,
        target=target,
        generated_at=datetime.now(timezone.utc).isoformat(),
        findings=findings,
        pattern_version=pattern_meta.get("version", "unknown"),
        pattern_sources=pattern_meta.get("sources", []),
    )


def render_summary(findings: List[Finding]) -> str:
    counts = {}
    for finding in findings:
        counts[finding.severity_label] = counts.get(finding.severity_label, 0) + 1
    lines = ["APKSpider Findings Summary", "=" * 28]
    if not findings:
        lines.append("No findings matched the current pattern set.")
        return "\n".join(lines)

    for severity in ["critical", "high", "medium", "low", "info"]:
        if severity in counts:
            lines.append(f"{severity.title()}: {counts[severity]}")

    lines.append("")
    for finding in findings:
        lines.append(f"- [{finding.severity_label.upper()}] {finding.title} ({finding.finding_id})")
        lines.append(f"  Impacted: {', '.join(finding.impacted_files)}")
        lines.append(f"  Evidence: {finding.evidence}")
        lines.append(f"  Confidence: {finding.confidence} | Detection: {finding.detection_type}")
        lines.append("")
    return "\n".join(lines)
