import hashlib
import json
import os
from typing import Any, Dict, List

from enrichment import (
    build_references,
    build_remediation_steps,
    build_why_it_matters,
    infer_attack_mapping,
    infer_credential_misuse,
    maybe_ai_enrich,
)
from manifest import parse_manifest
from scan_store import ScanStore
from scoring import label_from_score, score_with_modifiers


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_report(report_dir: str) -> Dict[str, Any]:
    report_path = os.path.join(report_dir, "report.json")
    with open(report_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def persist_scan(
    report_dir: str,
    apk_path: str,
    decompiled_dir: str,
    scan_store: ScanStore,
    status: str = "complete",
    notes: str = "",
) -> int:
    report = _load_report(report_dir)
    metadata = report.get("metadata", {})
    findings = report.get("findings", [])

    manifest = parse_manifest(decompiled_dir)
    sha256 = _sha256_file(apk_path)

    scored_findings: List[Dict[str, Any]] = []
    risk_scores: List[float] = []

    for finding in findings:
        evidence = finding.get("evidence", "")
        category = finding.get("category", "")
        title = finding.get("title", "")
        description = finding.get("description", "")
        confidence = finding.get("confidence", "medium")
        severity = finding.get("severity_label", "medium")
        references = finding.get("references", [])
        masvs = finding.get("masvs", [])

        risk_result = score_with_modifiers(
            severity_label=severity,
            confidence=confidence,
            category=category,
            title=title,
            detection_type=finding.get("detection_type", ""),
            references=references,
        )
        risk_scores.append(risk_result.score)

        exploit_mapping = infer_attack_mapping(category, title, description, references)
        credential_misuse = infer_credential_misuse(category, evidence, title, description)
        references_payload = build_references(references, masvs, title)
        why_it_matters = build_why_it_matters(title, description, risk_result.score, risk_result.label)
        remediation_steps = build_remediation_steps(category)
        ai_payload = maybe_ai_enrich(title, description, evidence, remediation_steps, credential_misuse)

        scored_findings.append(
            {
                "pattern_id": finding.get("finding_id", ""),
                "category": category,
                "title": title,
                "severity": severity,
                "confidence": confidence,
                "cwe": ", ".join(references_payload.get("cwe", [])),
                "owasp_mstg": ", ".join(references_payload.get("owasp_mstg", [])),
                "masvs": ", ".join(references_payload.get("masvs", [])),
                "file_path": (finding.get("impacted_files") or [""])[0],
                "symbol": "",
                "description": description,
                "evidence": evidence,
                "recommendation": remediation_steps[0] if remediation_steps else "Review and remediate.",
                "risk_score": risk_result.score,
                "risk_label": risk_result.label,
                "risk_breakdown_json": json.dumps(risk_result.breakdown),
                "exploit_mapping_json": json.dumps(exploit_mapping),
                "credential_misuse_json": json.dumps(credential_misuse or {}),
                "references_json": json.dumps(references_payload),
                "why_it_matters": why_it_matters,
                "remediation_json": json.dumps(remediation_steps),
                "ai_enrichment_json": json.dumps(ai_payload or {}),
            }
        )

    overall_risk = round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0.0
    overall_label = label_from_score(overall_risk)

    scan_id = scan_store.create_scan(
        filename=os.path.basename(apk_path),
        sha256=sha256,
        package_name=manifest.get("package_name") or metadata.get("target", ""),
        version_name=manifest.get("version_name", ""),
        version_code=manifest.get("version_code", ""),
        min_sdk=manifest.get("min_sdk", ""),
        target_sdk=manifest.get("target_sdk", ""),
        permissions=manifest.get("permissions", []),
        overall_risk=overall_risk,
        status=status,
        notes=f"Overall risk: {overall_label}. {notes}".strip(),
    )
    if scored_findings:
        scan_store.add_findings(scan_id, scored_findings)
    return scan_id
