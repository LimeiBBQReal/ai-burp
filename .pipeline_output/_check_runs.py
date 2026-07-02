"""检查 GitHub Actions 运行状态."""
import requests, sys

TOKEN = "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"
OWNER = "LimeiBBQReal"
REPO = "ai-burp-recon"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

def get_log(run_id):
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/runs/{run_id}/logs"
    r = requests.get(url, headers=HEADERS, timeout=30, allow_redirects=True)
    if r.status_code == 200:
        return r.text
    # Try download url
    url2 = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/runs/{run_id}"
    r2 = requests.get(url2, headers=HEADERS, timeout=15).json()
    dl_url = r2.get("logs_url", "")
    if dl_url:
        r3 = requests.get(dl_url, headers=HEADERS, timeout=30, allow_redirects=True)
        return r3.text[:5000] if r3.status_code == 200 else f"Logs status: {r3.status_code}"
    return f"logs_url not available"

# Get latest 10 completed workflow_dispatch runs
url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/runs?per_page=15&event=workflow_dispatch"
r = requests.get(url, headers=HEADERS, timeout=15)
runs = r.json().get("workflow_runs", [])

for run in runs:
    wf = run["name"]
    conclusion = run.get("conclusion", "?")
    if not conclusion:
        continue
    rid = run["id"]
    created = run["created_at"][:19]
    print(f"[{conclusion:8s}] {created}  {wf:<30s}  id={rid}")
    if conclusion == "failure" and "Subdomain" in wf:
        print(f"  -> Fetching logs for run {rid} ...")
        logs = get_log(rid)
        print(f"  -> Logs (first 1500 chars):")
        print(logs[:1500])

print("\nDone")
