import json
import os
from typing import List

from __init__ import __version__
from patterns import load_pattern_metadata, load_patterns
from report import Finding, build_report, render_summary
from scanner import ScanConfig, scan_decompiled_dir


def _severity_counts(findings: List[Finding]) -> dict:
    counts = {}
    for finding in findings:
        counts[finding.severity_label] = counts.get(finding.severity_label, 0) + 1
    return counts


def run_analysis(decompiled_dir: str, output_dir: str, target: str) -> List[Finding]:
    patterns = load_patterns()
    pattern_meta = load_pattern_metadata()

    findings = scan_decompiled_dir(decompiled_dir, patterns, ScanConfig())
    report = build_report(
        tool="APKSpider",
        tool_version=__version__,
        target=target,
        findings=findings,
        pattern_meta=pattern_meta,
    )

    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "report.json")
    summary_path = os.path.join(output_dir, "summary.txt")
    summary_json_path = os.path.join(output_dir, "summary.json")

    with open(json_path, "w", encoding="utf-8") as handle:
        handle.write(report.to_json())

    with open(summary_path, "w", encoding="utf-8") as handle:
        handle.write(render_summary(findings))

    summary = {
        "target": target,
        "total_findings": len(findings),
        "severity_counts": _severity_counts(findings),
    }
    with open(summary_json_path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle)

    print(f"[✓] Report written to {json_path}")
    print(f"[✓] Summary written to {summary_path}")
    return findings
