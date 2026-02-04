# APKspider Dashboard Architecture Notes

## Data flow overview
1. **Upload**
   - Users upload APK/XAPK files via the API or dashboard upload UI.
   - Chunked upload endpoints persist chunk data to `APP_DATA_DIR/chunked_uploads`, reassemble files, validate size/extension, and checksum the final APK.

2. **Job processing**
   - The API persists job metadata in `jobs.db` and enqueues a background RQ worker.
   - The worker validates the APK/XAPK, extracts/decompiles, runs analysis, and writes the JSON report to the job report directory.

3. **Persistence**
   - After analysis completes, the worker stores scan metadata and findings in `scan_results.db` via `ScanStore`.
   - Risk scores are recomputed using severity/confidence plus contextual modifiers (reachability, credential exposure, known CVEs).

4. **Dashboard**
   - The FastAPI dashboard reads from the scan database and renders Jinja2 templates for overview, scan detail, findings list, and finding detail pages.
   - JSON and SARIF exports are generated directly from the database so CI integrations do not depend on filesystem paths.

## Storage locations
- `APP_DATA_DIR/uploads`: finalized uploads
- `APP_DATA_DIR/chunked_uploads`: temporary upload sessions
- `APP_DATA_DIR/reports`: job reports
- `APP_DATA_DIR/scan_results.db`: persisted scan results for the dashboard
- `APP_DATA_DIR/jobs.db`: background job metadata

## AI enrichment
- Optional AI enrichment runs only when `ENABLE_AI_ENRICHMENT=true` and `OPENAI_API_KEY` is set.
- Only minimal metadata (title, description, evidence snippet) is sent for enrichment; full APK content is never sent.
