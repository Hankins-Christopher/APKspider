#!/usr/bin/env sh
set -eu

echo "[1/3] Checking for disallowed runtime apkspider imports..."
if rg -n "from apkspider|import apkspider" api ./*.py --glob '!**/tests/**'; then
  echo "Found disallowed runtime imports."
  exit 1
fi

echo "[2/3] docker compose ps"
docker compose ps

echo "[3/3] API reachability from web"
docker compose exec web sh -lc "wget -S -O- http://api:8000/dashboard 2>&1 | head -n 5"

echo "Verification passed."
