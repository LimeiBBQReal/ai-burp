"""通过 GitHub API 触发所有 10 个 recon workflow."""
import requests, time, sys

TOKEN = "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"
OWNER = "LimeiBBQReal"
REPO = "ai-burp-recon"
TARGET = "CartManager.net"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

WORKFLOWS = [
    "recon-subdomain.yml",
    "recon-dns.yml",
    "recon-portscan.yml",
    "recon-banner.yml",
    "recon-dir.yml",
    "recon-params.yml",
    "recon-js.yml",
    "recon-cidr.yml",
    "recon-urls.yml",
    "recon-deep.yml",
]

def trigger(wf_name):
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/workflows/{wf_name}/dispatches"
    body = {"ref": "main", "inputs": {"target": TARGET}}
    r = requests.post(url, headers=HEADERS, json=body, timeout=15)
    if r.status_code == 204:
        print(f"  [OK] {wf_name} -> triggered")
    else:
        print(f"  [ERR] {wf_name} -> {r.status_code}: {r.text[:120]}")
    return r.status_code

print(f"触发所有 workflow, target={TARGET}")
print(f"共 {len(WORKFLOWS)} 个\n")

for i, wf in enumerate(WORKFLOWS, 1):
    trigger(wf)
    if i < len(WORKFLOWS):
        time.sleep(0.5)

print("\n完成! 前往 https://github.com/LimeiBBQReal/ai-burp-recon/actions 查看进度")
