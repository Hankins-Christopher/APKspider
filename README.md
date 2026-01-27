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
