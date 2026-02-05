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

The primary output is a dashboard UI served by the FastAPI service:

- Dashboard UI: http://localhost:8000/dashboard
- JSON/SARIF export available from each scan detail page.

Uploads use resumable chunked endpoints:
- `POST /v1/upload/init`
- `POST /v1/upload/chunk`
- `POST /v1/upload/finish`

## Install (Docker)

```bash
git clone https://github.com/Hankins-Christopher/APKspider.git
cd APKspider
cp .env.example .env
```

1. Edit `.env` and set `HOST_IP` to the host IP or DNS name reachable by the browser client.
2. Optionally adjust `WEB_PORT` and `API_PORT`.
3. First run only (or whenever the named volume is recreated):

```bash
docker compose run --rm init-perms
```

4. Rebuild web with the current env values baked into the Next.js client bundle:

```bash
docker compose build --no-cache web
```

5. Start the stack:

```bash
docker compose up -d --build
```

- Web UI: `${WEB_ORIGIN}`
- API (outside Docker, if port is published): `${API_BASE_URL}`
- API (inside Docker Compose, from containers): `http://api:8000`
- Optional reverse proxy (nginx): `docker compose --profile proxy up --build` (proxy on http://localhost:8080)

## Verification

```bash
docker compose exec web sh -lc 'getent hosts api && wget -S -O- http://api:8000/dashboard 2>&1 | head -n 12'
```

From your laptop/browser:
- Open `${WEB_ORIGIN}`
- Open `${API_BASE_URL}/dashboard`

## Troubleshooting: analysis service unreachable

- `api` is a Docker-internal hostname. Browsers outside Docker cannot resolve `http://api:8000`.
- The browser must call the API via `${API_BASE_URL}` derived from `.env` and baked into `NEXT_PUBLIC_API_BASE_URL` at build time.
- If `.env` changes, rebuild web so Next.js re-bakes client-side config.

```bash
docker compose build --no-cache web
docker compose up -d --build web
```

Checks:

```bash
docker compose exec web sh -lc 'grep -RIn "http://api:8000" /app/.next 2>/dev/null | head -n 5 || true'
docker compose exec web sh -lc 'grep -RIn "${HOST_IP}:${API_PORT}" /app/.next 2>/dev/null | head -n 5 || true'
```

## Configuration

Environment variables (defaults shown):

You can also check `config/security.example.yaml` for baseline values.

- `APP_DATA_DIR=/var/lib/apkspider` — persistent job storage
- `MAX_UPLOAD_BYTES=262144000` (250MB)
- `UPLOAD_CHUNK_BYTES=5242880` (5MB chunks for resumable uploads)
- `UPLOAD_SESSION_TTL_SECONDS=3600`
- `MAX_EXTRACTED_BYTES=1073741824` (1GB)
- `MAX_EXTRACT_FILES=10000`
- `MAX_EXTRACT_FILE_BYTES=209715200` (200MB)
- `JOB_TIMEOUT_SECONDS=600`
- `JOB_CPU_SECONDS=600`
- `JOB_MEMORY_BYTES=2147483648`
- `JOB_FD_LIMIT=256`
- `JOB_NPROC_LIMIT=128`
- `DISABLE_JOB_NETWORK=true`
- `API_ORIGIN=http://$HOST_IP:$WEB_PORT`
- `ALLOWED_ORIGINS=http://$HOST_IP:$WEB_PORT,http://localhost:$WEB_PORT`
- `SCAN_DB_PATH=/var/lib/apkspider/scan_results.db`

Optional AI enrichment:

- `ENABLE_AI_ENRICHMENT=true`
- `OPENAI_API_KEY=<token>`

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
- **Reverse proxy settings (nginx)**:
  - `client_max_body_size 250m;`
  - `proxy_read_timeout 600s;`
  - `proxy_connect_timeout 600s;`
  - `proxy_send_timeout 600s;`

## CLI usage

Scan from the CLI and persist results for the dashboard:

```bash
python main.py scan --apk /path/to/app.apk --output ./output --save-db ./scan_results.db
```

Serve the dashboard + API locally:

```bash
python main.py serve --host 0.0.0.0 --port 8080 --db ./scan_results.db
```

## Development

- API dependencies: `api/requirements.txt`
- Web dependencies: `web/package.json`
- Tests: `pytest`

> Note: This stack is intended for internal use. Deploying on the open internet requires additional hardening (WAF, full container sandboxing, secrets management, and audit logging).
