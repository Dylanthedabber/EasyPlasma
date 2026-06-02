#!/bin/bash
# Watches for new/updated files and pushes to EasyPlasma GitHub repo.
# Run once: bash push.sh
# Or keep running: watch -n 30 bash push.sh

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_DIR"

git add -A

# Check if there's anything to commit
if git diff --cached --quiet; then
    echo "[=] Nothing new to push"
    exit 0
fi

STAMP=$(date '+%Y-%m-%d %H:%M')
git commit -m "update $STAMP"
git push origin main 2>&1

echo "[+] Pushed to EasyPlasma"
