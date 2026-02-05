import json
import os
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from api.app.auth import basic_auth
from api.app.config import settings
from scan_store import ScanStore
from scoring import label_from_score

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")

templates = Jinja2Templates(directory=TEMPLATES_DIR)
router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def _scan_db_path() -> str:
    if settings.scan_db_path:
        return settings.scan_db_path
    return os.path.join(settings.app_data_dir, "scan_results.db")


def _store() -> ScanStore:
    return ScanStore(_scan_db_path())


def _load_findings(scan_id: int) -> List[Dict]:
    store = _store()
    return [
        {
            **finding.__dict__,
            "risk_breakdown": json.loads(finding.risk_breakdown_json),
            "exploit_mapping": json.loads(finding.exploit_mapping_json),
            "credential_misuse": json.loads(finding.credential_misuse_json),
            "references": json.loads(finding.references_json),
            "remediation": json.loads(finding.remediation_json),
            "ai_enrichment": json.loads(finding.ai_enrichment_json),
        }
        for finding in store.list_findings(scan_id)
    ]


def _severity_counts(findings: List[Dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for finding in findings:
        severity = (finding.get("severity") or "").lower()
        counts[severity] = counts.get(severity, 0) + 1
    return counts


@router.get("", response_class=HTMLResponse)
async def dashboard_home(request: Request, _: None = Depends(basic_auth)):
    store = _store()
    scans = store.list_scans(limit=50)
    return templates.TemplateResponse(
        "dashboard_home.html",
        {"request": request, "scans": scans},
    )


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: int, _: None = Depends(basic_auth)):
    store = _store()
    try:
        scan = store.get_scan(scan_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = _load_findings(scan_id)
    severity_counts = _severity_counts(findings)
    categories = {}
    for finding in findings:
        category = finding.get("category") or "Uncategorized"
        categories[category] = categories.get(category, 0) + 1
    top_findings = sorted(findings, key=lambda item: item.get("risk_score", 0.0), reverse=True)[:5]
    permissions = json.loads(scan.permissions_json)

    overall_label = label_from_score(scan.overall_risk)
    return templates.TemplateResponse(
        "scan_detail.html",
        {
            "request": request,
            "scan": scan,
            "findings": findings,
            "severity_counts": severity_counts,
            "categories": categories,
            "top_findings": top_findings,
            "permissions": permissions,
            "overall_label": overall_label,
        },
    )


@router.get("/scans/{scan_id}/findings", response_class=HTMLResponse)
async def findings_list(
    request: Request,
    scan_id: int,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    query: Optional[str] = None,
    sort: str = "risk",
    _: None = Depends(basic_auth),
):
    store = _store()
    try:
        scan = store.get_scan(scan_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = _load_findings(scan_id)
    filtered = []
    for finding in findings:
        if severity and finding.get("severity", "").lower() != severity.lower():
            continue
        if category and finding.get("category", "").lower() != category.lower():
            continue
        if query:
            haystack = " ".join(
                [
                    finding.get("title", ""),
                    finding.get("description", ""),
                    finding.get("file_path", ""),
                    finding.get("category", ""),
                ]
            ).lower()
            if query.lower() not in haystack:
                continue
        filtered.append(finding)

    if sort == "severity":
        filtered.sort(key=lambda item: item.get("severity", ""))
    else:
        filtered.sort(key=lambda item: item.get("risk_score", 0.0), reverse=True)

    return templates.TemplateResponse(
        "findings_list.html",
        {
            "request": request,
            "scan": scan,
            "findings": filtered,
            "severity": severity or "",
            "category": category or "",
            "query": query or "",
            "sort": sort,
        },
    )


@router.get("/scans/{scan_id}/findings/{finding_id}", response_class=HTMLResponse)
async def finding_detail(request: Request, scan_id: int, finding_id: int, _: None = Depends(basic_auth)):
    store = _store()
    try:
        scan = store.get_scan(scan_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = _load_findings(scan_id)
    finding = None
    for item in findings:
        if item.get("id") == finding_id:
            finding = item
            break
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    index = [item.get("id") for item in findings].index(finding_id)
    prev_id = findings[index - 1]["id"] if index > 0 else None
    next_id = findings[index + 1]["id"] if index + 1 < len(findings) else None

    return templates.TemplateResponse(
        "finding_detail.html",
        {
            "request": request,
            "scan": scan,
            "finding": finding,
            "prev_id": prev_id,
            "next_id": next_id,
            "total_findings": len(findings),
            "index": index + 1,
        },
    )


@router.get("/scans/{scan_id}/export.json")
async def export_json(scan_id: int, _: None = Depends(basic_auth)):
    store = _store()
    try:
        payload = store.export_scan_json(scan_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(payload)


@router.get("/scans/{scan_id}/export.sarif")
async def export_sarif(scan_id: int, _: None = Depends(basic_auth)):
    store = _store()
    try:
        payload = store.export_scan_sarif(scan_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(payload)
