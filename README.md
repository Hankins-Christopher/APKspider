```
      ___           ___         ___                                             
     /\  \         /\  \       /|  |                                            
    /::\  \       /::\  \     |:|  |                                            
   /:/\:\  \     /:/\:\__\    |:|  |                                            
  /:/ /::\  \   /:/ /:/  /  __|:|  |                                            
 /:/_/:/\:\__\ /:/_/:/  /  /\ |:|__|____                                        
 \:\/:/  \/__/ \:\/:/  /   \:\/:::::/__/                                        
  \::/__/       \::/__/     \::/~~/~                                            
   \:\  \        \:\  \      \:\~~\                                             
    \:\__\        \:\__\      \:\__\                                            
     \/__/         \/__/       \/__/                                            
      ___           ___                                   ___           ___     
     /\__\         /\  \                   _____         /\__\         /\  \    
    /:/ _/_       /::\  \     ___         /::\  \       /:/ _/_       /::\  \   
   /:/ /\  \     /:/\:\__\   /\__\       /:/\:\  \     /:/ /\__\     /:/\:\__\  
  /:/ /::\  \   /:/ /:/  /  /:/__/      /:/  \:\__\   /:/ /:/ _/_   /:/ /:/  /  
 /:/_/:/\:\__\ /:/_/:/  /  /::\  \     /:/__/ \:|__| /:/_/:/ /\__\ /:/_/:/__/___
 \:\/:/ /:/  / \:\/:/  /   \/\:\  \__  \:\  \ /:/  / \:\/:/ /:/  / \:\/:::::/  /
  \::/ /:/  /   \::/__/     ~~\:\/\__\  \:\  /:/  /   \::/_/:/  /   \::/~~/~~~~ 
   \/_/:/  /     \:\  \        \::/  /   \:\/:/  /     \:\/:/  /     \:\~~\     
     /:/  /       \:\__\       /:/  /     \::/  /       \::/  /       \:\__\    
     \/__/         \/__/       \/__/       \/__/         \/__/         \/__/    
```

# APKSpider - Automated APK Extraction & Analysis Tool

APKSpider is a Python tool for **downloading, extracting, decompiling, and scanning APKs** for sensitive files and embedded secrets. This version prioritizes deterministic heuristics and reproducible scoring over LLM-only analysis.

## Highlights
- **Local APK analysis** (`--apk`) without any web automation.
- **HTTP-first APK acquisition** with Playwright only as an explicit fallback.
- **Deterministic sensitive file detection** using a curated, versioned pattern list.
- **CVSS-style scoring** with reproducible severity labels.
- **JSON report + human-readable summary** outputs.

---

## Disclaimer

This tool is for educational and ethical security testing purposes only. Ensure you have permission before analyzing third-party apps.

---

## Requirements

- **Python 3.9+**
- **`apktool`** (installed and available in your system path)

Playwright is **optional** and only used if `--playwright-fallback` is specified.

---

## Install

```bash
pip install -r requirements.txt
```

---

## Usage

### Analyze a local APK (no web automation)
```bash
python3 main.py --apk /path/to/app.apk
```

### Download via direct URL
```bash
python3 main.py https://example.com/path/to/app.apk
```

### Download by package name (HTTP-first, Playwright optional)
```bash
python3 main.py com.example.app
```

If HTTP parsing fails and you want to allow a last-resort browser fallback:
```bash
python3 main.py com.example.app --playwright-fallback
```

### Output directory
```bash
python3 main.py com.example.app --output /tmp/apkspider
```

---

## Output

APKSpider writes:
- `analysis_report/report.json` — structured JSON report
- `analysis_report/summary.txt` — human-readable summary

---

## Design decisions: sensitive file discovery

**Primary strategy: versioned deterministic pattern list**.

Rationale:
- Predictable and reproducible detection behavior.
- Easy to audit and update from public sources.
- No required API keys or rate limits.

The default pattern list lives in `data/sensitive_patterns_v1.json`. It contains path and content signatures for common secrets and sensitive artifacts (dotenv files, private keys, JWTs, cloud keys, backup files, databases).

### Update strategy
- Track upstream lists (e.g., SecLists, OWASP MASVS/MSTG references).
- Add new patterns by extending the JSON list and incrementing its version.
- Add tests for new patterns before release.

---

## Scoring model

Findings are mapped to a **CVSS v3.1-style severity** using deterministic rules:
- Base severity provided by the pattern list.
- Confidence modifier applied consistently.
- Severity labels derived from the numeric score (Critical/High/Medium/Low/Info).

Each finding includes a stable schema: id, title, description, evidence (redacted), impacted files, severity score, severity label, rationale, references, and MASVS mapping where applicable.

---

## How to test locally

```bash
pytest
```

---

## Contributing

We welcome contributions to APKSpider! Please follow standard PR practices and include tests for new detection logic.

---

# Secure web console (Next.js + FastAPI)

APKSpider now includes a hardened web application for secure APK/XAPK uploads and background analysis. The web UI intentionally **does not** accept URLs or package names; only direct file uploads are supported.

## Quick start (Docker)

```bash
docker compose up --build
```

- Web UI: http://localhost:3000
- API: http://localhost:8000
- Optional reverse proxy (nginx): `docker compose --profile proxy up --build` (proxy on http://localhost:8080)

## Configuration

Environment variables (defaults shown):

You can also check `config/security.example.yaml` for baseline values.

- `APP_DATA_DIR=/var/lib/apkspider` — persistent job storage
- `MAX_UPLOAD_BYTES=262144000` (250MB)
- `MAX_EXTRACTED_BYTES=1073741824` (1GB)
- `MAX_EXTRACT_FILES=10000`
- `MAX_EXTRACT_FILE_BYTES=209715200` (200MB)
- `JOB_TIMEOUT_SECONDS=600`
- `JOB_CPU_SECONDS=600`
- `JOB_MEMORY_BYTES=2147483648`
- `JOB_FD_LIMIT=256`
- `JOB_NPROC_LIMIT=128`
- `DISABLE_JOB_NETWORK=true`
- `ALLOWED_ORIGINS=http://localhost:3000`

Optional basic auth:

- `BASIC_AUTH_ENABLED=true`
- `BASIC_AUTH_USERNAME=admin`
- `BASIC_AUTH_PASSWORD_HASH=<bcrypt hash>`

## Threat model summary

Assume hostile inputs:
- Malicious archives attempting zip slip or decompression bombs.
- Polyglot files or content-type spoofing.
- Path traversal, unicode tricks, and symlink abuse.
- Untrusted APK payloads aiming for RCE through analysis tools.

## Security controls

- **Upload hardening**: strict size limits, extension validation plus ZIP signature and MIME sniffing, and server-side filenames.
- **Safe extraction**: zip slip prevention, symlink rejection, per-file size caps, total size caps, and file count limits.
- **Process isolation**: non-root containers, `no-new-privileges`, capability drops, read-only root filesystem, resource limits, and job timeouts.
- **Network restrictions**: network access disabled by default for analysis jobs (best-effort, configurable).
- **Web protections**: CORS restricted to the UI, rate limiting on uploads, security headers, and optional basic auth.
- **Output safety**: report zipping ignores symlinks, summary JSON is generated server-side, and UI renders text-only content.

## Operational guidance

- **Where files live**: job artifacts in `$APP_DATA_DIR` (uploads, logs, reports, work).
- **Cleanup**: disable `KEEP_JOB_DIRS` to auto-delete workdirs after completion.
- **Raising limits**: adjust `MAX_UPLOAD_BYTES` and `MAX_EXTRACTED_BYTES` and update reverse proxy `client_max_body_size` when applicable.

## Development

- API dependencies: `requirements-api.txt` (Docker) and `api/requirements.txt` (dev)
- Web dependencies: `web/package.json`
- Tests: `pytest`

> Note: This stack is intended for internal use. Deploying on the open internet requires additional hardening (WAF, full container sandboxing, secrets management, and audit logging).
