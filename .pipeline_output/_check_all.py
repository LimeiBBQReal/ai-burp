"""检查 repo 中 out/ 目录的最新状态 + 最近 workflow run 概况 + 失败任务日志."""
import requests

TOKEN = "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"
OWNER = "LimeiBBQReal"
REPO = "ai-burp-recon"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

def get_log(run_id, output_char_limit=2000):
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/runs/{run_id}/logs"
    r = requests.get(url, headers=HEADERS, timeout=60, stream=True)
    if r.status_code != 200:
        return f"Log download failed: HTTP {r.status_code}"
    import zipfile, io
    z = zipfile.ZipFile(io.BytesIO(r.content))
    parts = []
    total = 0
    for name in z.namelist():
        text = z.read(name).decode("utf-8", errors="replace")
        total += len(text)
        if total > output_char_limit:
            break
        parts.append(f"--- {name} ---\n{text}")
    return "\n".join(parts)

# 1. 检查最近 workflow runs
print("=== 最近 workflow runs ===")
url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/runs?per_page=15&event=workflow_dispatch"
r = requests.get(url, headers=HEADERS, timeout=15)
runs = r.json().get("workflow_runs", [])

for run in runs:
    rid = run["id"]
    wf = run["name"]
    status = run.get("status") or "?"
    conclusion = run.get("conclusion") or "?"
    created = run["created_at"][:19]
    commit_sha = (run.get("head_sha") or "?")[:8]
    print(f"[{status:7s}/{conclusion:8s}] {created}  {wf:<30s}  commit={commit_sha}  id={rid}")

# 2. 检查 out/ 目录
print("\n=== out/ 目录 ===")
url2 = f"https://api.github.com/repos/{OWNER}/{REPO}/contents/out"
r2 = requests.get(url2, headers=HEADERS, timeout=15)
if r2.status_code == 200:
    files = r2.json()
    for f in files:
        print(f"  {f['name']:40s} {f['size']:>8} bytes")
else:
    print(f"  (status {r2.status_code})")

print("\n=== 失败任务分析 ===")
for run in runs:
    rid = run["id"]
    wf = run["name"]
    status = run.get("status") or "?"
    conclusion = run.get("conclusion") or "?"
    created = run["created_at"][:19]
    commit_sha = (run.get("head_sha") or "?")[:8]
    if conclusion == "failure":
        print(f"\n  --- {wf} ({created}, commit={commit_sha}, id={rid}) ---")
        logs = get_log(rid, output_char_limit=2000)
        print(logs)
