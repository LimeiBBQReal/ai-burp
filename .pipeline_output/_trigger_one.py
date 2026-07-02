"""触发指定 workflow."""
import requests, sys

TOKEN = "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"
OWNER = "LimeiBBQReal"
REPO = "ai-burp-recon"
TARGET = "CartManager.net"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

WORKFLOW = sys.argv[1] if len(sys.argv) > 1 else "recon-subdomain.yml"

url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/workflows/{WORKFLOW}/dispatches"
body = {"ref": "main", "inputs": {"target": TARGET}}
r = requests.post(url, headers=HEADERS, json=body, timeout=15)
if r.status_code == 204:
    print(f"[OK] {WORKFLOW} triggered for {TARGET}")
else:
    print(f"[ERR] {r.status_code}: {r.text[:200]}")
