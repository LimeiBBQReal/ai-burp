"""检查最新的 workflow 运行情况和 out/ 目录文件."""
import requests

TOKEN = "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"
OWNER = "LimeiBBQReal"
REPO = "ai-burp-recon"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

print("=== 最新 workflow runs ===")
url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/runs?per_page=15&event=workflow_dispatch"
r = requests.get(url, headers=HEADERS, timeout=15)
for run in r.json().get("workflow_runs", []):
    status = run.get("status") or "?"
    conclusion = run.get("conclusion") or "?"
    created = run["created_at"][:19]
    commit_sha = (run.get("head_sha") or "?")[:8]
    name = run["name"]
    print(f"[{status:7s}/{conclusion:8s}] {created}  {name:<30s}  commit={commit_sha}")

print("\n=== out/ 目录 ===")
url2 = f"https://api.github.com/repos/{OWNER}/{REPO}/contents/out"
r2 = requests.get(url2, headers=HEADERS, timeout=15)
if r2.status_code == 200:
    for f in r2.json():
        print(f"  {f['name']:40s} {f['size']:>8} bytes")
else:
    print(f"  (status {r2.status_code})")
