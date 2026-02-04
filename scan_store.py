import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

_DB_LOCK = threading.Lock()


@dataclass(frozen=True)
class ScanRecord:
    id: int
    created_at: str
    status: str
    filename: str
    sha256: str
    package_name: str
    version_name: str
    version_code: str
    min_sdk: str
    target_sdk: str
    permissions_json: str
    overall_risk: float
    notes: str


@dataclass(frozen=True)
class FindingRecord:
    id: int
    scan_id: int
    pattern_id: str
    category: str
    title: str
    severity: str
    confidence: str
    cwe: str
    owasp_mstg: str
    masvs: str
    file_path: str
    symbol: str
    description: str
    evidence: str
    recommendation: str
    risk_score: float
    risk_label: str
    risk_breakdown_json: str
    exploit_mapping_json: str
    credential_misuse_json: str
    references_json: str
    why_it_matters: str
    remediation_json: str
    ai_enrichment_json: str


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def init_db(db_path: str) -> None:
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with _DB_LOCK:
        conn = _connect(db_path)
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    version_name TEXT NOT NULL,
                    version_code TEXT NOT NULL,
                    min_sdk TEXT NOT NULL,
                    target_sdk TEXT NOT NULL,
                    permissions_json TEXT NOT NULL,
                    overall_risk REAL NOT NULL,
                    notes TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    pattern_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    cwe TEXT NOT NULL,
                    owasp_mstg TEXT NOT NULL,
                    masvs TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    symbol TEXT NOT NULL,
                    description TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    recommendation TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    risk_label TEXT NOT NULL,
                    risk_breakdown_json TEXT NOT NULL,
                    exploit_mapping_json TEXT NOT NULL,
                    credential_misuse_json TEXT NOT NULL,
                    references_json TEXT NOT NULL,
                    why_it_matters TEXT NOT NULL,
                    remediation_json TEXT NOT NULL,
                    ai_enrichment_json TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
                """
            )
            conn.commit()
        finally:
            conn.close()


class ScanStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        init_db(self.db_path)

    def create_scan(
        self,
        filename: str,
        sha256: str,
        package_name: str,
        version_name: str,
        version_code: str,
        min_sdk: str,
        target_sdk: str,
        permissions: List[str],
        overall_risk: float,
        status: str = "complete",
        notes: str = "",
    ) -> int:
        created_at = _now()
        with _DB_LOCK:
            conn = _connect(self.db_path)
            try:
                cursor = conn.execute(
                    """
                    INSERT INTO scans (
                        created_at, status, filename, sha256, package_name, version_name, version_code,
                        min_sdk, target_sdk, permissions_json, overall_risk, notes
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        created_at,
                        status,
                        filename,
                        sha256,
                        package_name,
                        version_name,
                        version_code,
                        min_sdk,
                        target_sdk,
                        json.dumps(permissions),
                        overall_risk,
                        notes,
                    ),
                )
                conn.commit()
                return int(cursor.lastrowid)
            finally:
                conn.close()

    def add_findings(self, scan_id: int, findings: Iterable[Dict[str, Any]]) -> None:
        with _DB_LOCK:
            conn = _connect(self.db_path)
            try:
                conn.executemany(
                    """
                    INSERT INTO findings (
                        scan_id, pattern_id, category, title, severity, confidence, cwe, owasp_mstg, masvs,
                        file_path, symbol, description, evidence, recommendation, risk_score, risk_label,
                        risk_breakdown_json, exploit_mapping_json, credential_misuse_json, references_json,
                        why_it_matters, remediation_json, ai_enrichment_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            scan_id,
                            finding["pattern_id"],
                            finding["category"],
                            finding["title"],
                            finding["severity"],
                            finding["confidence"],
                            finding["cwe"],
                            finding["owasp_mstg"],
                            finding["masvs"],
                            finding["file_path"],
                            finding["symbol"],
                            finding["description"],
                            finding["evidence"],
                            finding["recommendation"],
                            finding["risk_score"],
                            finding["risk_label"],
                            finding["risk_breakdown_json"],
                            finding["exploit_mapping_json"],
                            finding["credential_misuse_json"],
                            finding["references_json"],
                            finding["why_it_matters"],
                            finding["remediation_json"],
                            finding["ai_enrichment_json"],
                        )
                        for finding in findings
                    ],
                )
                conn.commit()
            finally:
                conn.close()

    def list_scans(self, limit: int = 50) -> List[ScanRecord]:
        with _DB_LOCK:
            conn = _connect(self.db_path)
            try:
                rows = conn.execute(
                    """
                    SELECT id, created_at, status, filename, sha256, package_name, version_name, version_code,
                           min_sdk, target_sdk, permissions_json, overall_risk, notes
                    FROM scans ORDER BY created_at DESC LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            finally:
                conn.close()
        return [ScanRecord(**dict(row)) for row in rows]

    def get_scan(self, scan_id: int) -> ScanRecord:
        with _DB_LOCK:
            conn = _connect(self.db_path)
            try:
                row = conn.execute(
                    """
                    SELECT id, created_at, status, filename, sha256, package_name, version_name, version_code,
                           min_sdk, target_sdk, permissions_json, overall_risk, notes
                    FROM scans WHERE id = ?
                    """,
                    (scan_id,),
                ).fetchone()
            finally:
                conn.close()
        if not row:
            raise KeyError(scan_id)
        return ScanRecord(**dict(row))

    def list_findings(self, scan_id: int) -> List[FindingRecord]:
        with _DB_LOCK:
            conn = _connect(self.db_path)
            try:
                rows = conn.execute(
                    """
                    SELECT id, scan_id, pattern_id, category, title, severity, confidence, cwe, owasp_mstg,
                           masvs, file_path, symbol, description, evidence, recommendation, risk_score,
                           risk_label, risk_breakdown_json, exploit_mapping_json, credential_misuse_json,
                           references_json, why_it_matters, remediation_json, ai_enrichment_json
                    FROM findings WHERE scan_id = ? ORDER BY risk_score DESC, id ASC
                    """,
                    (scan_id,),
                ).fetchall()
            finally:
                conn.close()
        return [FindingRecord(**dict(row)) for row in rows]

    def get_finding(self, scan_id: int, finding_id: int) -> FindingRecord:
        with _DB_LOCK:
            conn = _connect(self.db_path)
            try:
                row = conn.execute(
                    """
                    SELECT id, scan_id, pattern_id, category, title, severity, confidence, cwe, owasp_mstg,
                           masvs, file_path, symbol, description, evidence, recommendation, risk_score,
                           risk_label, risk_breakdown_json, exploit_mapping_json, credential_misuse_json,
                           references_json, why_it_matters, remediation_json, ai_enrichment_json
                    FROM findings WHERE scan_id = ? AND id = ?
                    """,
                    (scan_id, finding_id),
                ).fetchone()
            finally:
                conn.close()
        if not row:
            raise KeyError(finding_id)
        return FindingRecord(**dict(row))

    def export_scan_json(self, scan_id: int) -> Dict[str, Any]:
        scan = self.get_scan(scan_id)
        findings = self.list_findings(scan_id)
        payload = {
            "metadata": {
                "scan_id": scan.id,
                "created_at": scan.created_at,
                "status": scan.status,
                "filename": scan.filename,
                "sha256": scan.sha256,
                "package_name": scan.package_name,
                "version_name": scan.version_name,
                "version_code": scan.version_code,
                "min_sdk": scan.min_sdk,
                "target_sdk": scan.target_sdk,
                "permissions": json.loads(scan.permissions_json),
                "overall_risk": scan.overall_risk,
                "notes": scan.notes,
            },
            "findings": [
                {
                    "id": finding.id,
                    "pattern_id": finding.pattern_id,
                    "category": finding.category,
                    "title": finding.title,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "cwe": finding.cwe,
                    "owasp_mstg": finding.owasp_mstg,
                    "masvs": finding.masvs,
                    "file_path": finding.file_path,
                    "symbol": finding.symbol,
                    "description": finding.description,
                    "evidence": finding.evidence,
                    "recommendation": finding.recommendation,
                    "risk_score": finding.risk_score,
                    "risk_label": finding.risk_label,
                    "risk_breakdown": json.loads(finding.risk_breakdown_json),
                    "exploit_mapping": json.loads(finding.exploit_mapping_json),
                    "credential_misuse": json.loads(finding.credential_misuse_json),
                    "references": json.loads(finding.references_json),
                    "why_it_matters": finding.why_it_matters,
                    "remediation": json.loads(finding.remediation_json),
                    "ai_enrichment": json.loads(finding.ai_enrichment_json),
                }
                for finding in findings
            ],
        }
        return payload

    def export_scan_sarif(self, scan_id: int) -> Dict[str, Any]:
        scan = self.get_scan(scan_id)
        findings = self.list_findings(scan_id)
        rules: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []
        for finding in findings:
            rule_id = finding.pattern_id or f"APKSPIDER-{finding.id}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "help": {"text": finding.why_it_matters},
                    "properties": {
                        "category": finding.category,
                        "severity": finding.severity,
                        "confidence": finding.confidence,
                        "cwe": finding.cwe,
                        "owasp_mstg": finding.owasp_mstg,
                        "masvs": finding.masvs,
                    },
                }
            result = {
                "ruleId": rule_id,
                "level": _sarif_level(finding.severity),
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path},
                            "region": {"snippet": {"text": finding.evidence}},
                        }
                    }
                ],
                "properties": {
                    "risk_score": finding.risk_score,
                    "risk_label": finding.risk_label,
                },
            }
            results.append(result)

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "APKspider",
                            "informationUri": "https://github.com/s0undsystem/apkspider",
                            "rules": list(rules.values()),
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "properties": {
                                "scan_id": scan.id,
                                "package_name": scan.package_name,
                                "overall_risk": scan.overall_risk,
                            },
                        }
                    ],
                    "results": results,
                }
            ],
        }
        return sarif


def _sarif_level(severity: str) -> str:
    normalized = (severity or "").lower()
    if normalized in {"critical", "high"}:
        return "error"
    if normalized in {"medium"}:
        return "warning"
    return "note"
