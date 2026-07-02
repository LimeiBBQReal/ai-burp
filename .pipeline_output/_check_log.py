"""获取 workflow run 中 'Run subdomain enum' 步骤的详细日志."""
import requests, zipfile, io, json

TOKEN = "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"
OWNER = "LimeiBBQReal"
REPO = "ai-burp-recon"
RUN_ID = 28331251881  # latest subdomain run (commit 3b086db)

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

# Get run detail to find log URL
url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/runs/{RUN_ID}"
r = requests.get(url, headers=HEADERS, timeout=15)
run = r.json()
print(f"Run: {run['name']}")
print(f"Conclusion: {run['conclusion']}")
print(f"Log URL: {run.get('logs_url', 'N/A')}")

# Get jobs
jurl = run["jobs_url"]
rj = requests.get(jurl, headers=HEADERS, timeout=15)
jobs = rj.json().get("jobs", [])
for job in jobs:
    print(f"\nJob: {job['name']} [{job.get('conclusion', '?')}]")
    steps = job.get("steps", [])
    for step in steps:
        sname = step["name"]
        sstatus = step["status"]
        sconclusion = step.get("conclusion", "?")
        slog = step.get("log", "")
        print(f"  {sname}: [{sconclusion}]")

# Try to get raw logs via the logs download
print("\n\n=== Trying to download logs ===")
try:
    log_url = run["logs_url"]
    r2 = requests.get(log_url, headers=HEADERS, timeout=60, stream=True)
    print(f"Log download response: {r2.status_code}")
    if r2.status_code == 200:
        # It's a zip file
        z = zipfile.ZipFile(io.BytesIO(r2.content))
        for name in z.namelist():
            print(f"  Log file: {name} ({len(z.read(name))} bytes)")
except Exception as e:
    print(f"Error: {e}")
    print("Trying alternative approach...")
    # Try the step log URL from annotations
    ann_url = run.get("check_suite_url", "")
    if ann_url:
        print(f"Check suite: {ann_url}")
