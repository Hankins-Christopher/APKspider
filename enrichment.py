import json
import os
import re
from typing import Any, Dict, List, Optional

import requests

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_session_key": re.compile(r"ASIA[0-9A-Z]{16}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "github_token": re.compile(r"ghp_[0-9A-Za-z]{36}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "stripe_secret": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
}

CATEGORY_ATTACK_MAPPING = {
    "secrets": ["Credential Access", "Exfiltration"],
    "exposure": ["Collection", "Exfiltration"],
    "network": ["Man-in-the-Middle", "Command and Control"],
    "crypto": ["Defense Evasion"],
    "storage": ["Collection", "Exfiltration"],
}

CATEGORY_REMEDIATION = {
    "secrets": [
        "Rotate and revoke the exposed credential immediately.",
        "Move secrets to server-side storage or a secure vault (no hardcoding in app assets).",
        "Use short-lived tokens with scoped permissions and device attestation.",
    ],
    "exposure": [
        "Remove sensitive artifacts from build outputs.",
        "Use build-time secrets injection with environment-specific configs.",
        "Add lint checks to prevent accidental file inclusion.",
    ],
    "network": [
        "Enforce TLS with certificate pinning where appropriate.",
        "Remove cleartext traffic allowances and upgrade endpoints to HTTPS.",
        "Validate hostnames and implement retry/backoff logic.",
    ],
    "crypto": [
        "Use modern cryptographic primitives (AES-GCM, SHA-256, Argon2).",
        "Avoid hardcoded keys and use the platform keystore.",
        "Rotate keys and document key management procedures.",
    ],
    "storage": [
        "Store sensitive data in encrypted storage (Android Keystore + EncryptedSharedPreferences).",
        "Avoid writing secrets to world-readable locations.",
        "Implement data minimization and retention policies.",
    ],
}


def _normalize(text: str) -> str:
    return (text or "").strip().lower()


def infer_attack_mapping(category: str, title: str, description: str, references: List[str]) -> Dict[str, Any]:
    normalized = _normalize(category)
    techniques = CATEGORY_ATTACK_MAPPING.get(normalized, ["Discovery", "Collection"])
    known_exploits = [ref for ref in references if "cve" in ref.lower()]
    return {
        "techniques": techniques,
        "known_exploits": known_exploits,
        "heuristic": True,
        "notes": "ATT&CK-like mapping based on category/title heuristics.",
    }


def _guess_secret_type(evidence: str, title: str, description: str) -> Optional[str]:
    haystack = " ".join([evidence or "", title or "", description or ""])
    for key, pattern in SECRET_PATTERNS.items():
        if pattern.search(haystack):
            return key.replace("_", " ").title()
    if any(word in haystack.lower() for word in ["api key", "token", "secret", "password", "credential"]):
        return "Generic API Token"
    return None


def infer_credential_misuse(category: str, evidence: str, title: str, description: str) -> Optional[Dict[str, Any]]:
    normalized = _normalize(category)
    if normalized not in {"secrets", "exposure", "storage"}:
        return None
    secret_type = _guess_secret_type(evidence, title, description)
    if not secret_type:
        return None
    return {
        "secret_type": secret_type,
        "best_effort_inference": True,
        "likely_abuse_scenarios": [
            "API abuse leading to quota exhaustion or unexpected charges.",
            "Data exfiltration from backend services.",
            "Impersonation of the mobile client to access protected endpoints.",
        ],
        "potential_targets": [
            "Cloud APIs (AWS/GCP/Azure)",
            "Firebase or analytics services",
            "Payment providers or third-party SDKs",
        ],
        "immediate_response": [
            "Revoke/rotate the credential.",
            "Audit recent usage and add detection rules for anomalous traffic.",
            "Update the mobile app build to remove the credential.",
        ],
        "remediation": [
            "Move secrets to a backend service and issue short-lived tokens.",
            "Use device attestation and per-user scopes.",
            "Implement keyless workflows when possible.",
        ],
    }


def build_why_it_matters(title: str, description: str, risk_score: float, risk_label: str) -> str:
    return (
        f"{title} raises a {risk_label} risk (score {risk_score}). {description} "
        "If exploited, it could expose sensitive data or weaken the trust boundary between the app and backend."
    )


def build_remediation_steps(category: str) -> List[str]:
    normalized = _normalize(category)
    return CATEGORY_REMEDIATION.get(
        normalized,
        [
            "Review the finding and remove sensitive artifacts from the build.",
            "Add automated checks to prevent reintroduction.",
            "Retest after applying fixes.",
        ],
    )


def build_references(references: List[str], masvs: List[str], title: str) -> Dict[str, Any]:
    cwe_matches = []
    for ref in references:
        match = re.search(r"CWE-\d+", ref, re.IGNORECASE)
        if match:
            cwe_matches.append(match.group(0).upper())
    owasp_mstg = masvs or []
    if not owasp_mstg and "storage" in title.lower():
        owasp_mstg = ["MSTG-STORAGE-1"]
    return {
        "references": references,
        "cwe": cwe_matches,
        "owasp_mstg": owasp_mstg,
        "masvs": masvs,
    }


def maybe_ai_enrich(
    title: str,
    description: str,
    evidence: str,
    remediation_steps: List[str],
    credential_misuse: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    if os.getenv("ENABLE_AI_ENRICHMENT", "false").lower() != "true":
        return {}
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return {}

    prompt = (
        "Provide a concise security analyst note for a mobile finding. "
        "Include why it matters, remediation steps, and abuse scenarios. "
        "Use the evidence snippet as context but do not include secrets verbatim.\n\n"
        f"Title: {title}\nDescription: {description}\nEvidence: {evidence}\n"
        f"Remediation (current): {', '.join(remediation_steps)}\n"
        f"Credential misuse: {json.dumps(credential_misuse) if credential_misuse else 'None'}"
    )

    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": "You are a mobile security reviewer."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        },
        timeout=20,
    )
    if not response.ok:
        return {}
    payload = response.json()
    content = payload.get("choices", [{}])[0].get("message", {}).get("content", "")
    return {"ai_summary": content, "ai_generated": True}
