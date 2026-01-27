import os
from typing import List

from apkspider import __version__
from apkspider.patterns import load_pattern_metadata, load_patterns
from apkspider.report import Finding, build_report, render_summary
from apkspider.scanner import ScanConfig, scan_decompiled_dir


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

    with open(json_path, "w", encoding="utf-8") as handle:
        handle.write(report.to_json())

    with open(summary_path, "w", encoding="utf-8") as handle:
        handle.write(render_summary(findings))

    print(f"[✓] Report written to {json_path}")
    print(f"[✓] Summary written to {summary_path}")
    return findings
