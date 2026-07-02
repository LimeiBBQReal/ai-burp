"""检查最近的 subdomain run 状态, 看 .enc 是否被提交."""
import requests, zipfile, io

TOKEN = "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"
OWNER = "LimeiBBQReal"
REPO = "ai-burp-recon"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

# Get latest workflow_dispatch runs
url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/runs?per_page=10&event=workflow_dispatch"
r = requests.get(url, headers=HEADERS, timeout=15)
runs = r.json().get("workflow_runs", [])

for run in runs:
    rid = run["id"]
    wf = run["name"]
    conclusion = run.get("conclusion", "?")
    created = run["created_at"][:19]
    commit_sha = run["head_sha"][:8]
    print(f"[{conclusion:8s}] {created}  {wf:<30s}  commit={commit_sha}  id={rid}")

# Also check the repo's latest commit to see if out/ files exist
print("\n=== 检查仓库中最近的 out/ 文件 ===")
url2 = f"https://api.github.com/repos/{OWNER}/{REPO}/contents/out"
r2 = requests.get(url2, headers=HEADERS, timeout=15)
if r2.status_code == 200:
    files = r2.json()
    for f in files:
        print(f"  {f['name']:40s} {f['size']:>8} bytes  {f['sha'][:8]}")
else:
    print(f"  out/ 目录不存在或无法访问: {r2.status_code}")
