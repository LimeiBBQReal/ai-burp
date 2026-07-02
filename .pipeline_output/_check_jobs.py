"""通过 GitHub API 查询最近的 workflow run 详情和 jobs 状态."""
import requests

TOKEN = "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"
OWNER = "LimeiBBQReal"
REPO = "ai-burp-recon"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

# Get latest workflow_dispatch runs
url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/runs?per_page=15&event=workflow_dispatch"
r = requests.get(url, headers=HEADERS, timeout=15)
runs = r.json().get("workflow_runs", [])

for run in runs:
    rid = run["id"]
    wf = run["name"]
    conclusion = run.get("conclusion", "?")
    created = run["created_at"][:19]
    commit_sha = run["head_sha"][:8]
    print(f"\n=== [{conclusion}] {wf} (id={rid}, commit={commit_sha}) ===")
    print(f"  Created: {created}")

    # Get jobs for this run
    jurl = run["jobs_url"]
    rj = requests.get(jurl, headers=HEADERS, timeout=15)
    if rj.status_code == 200:
        jobs = rj.json().get("jobs", [])
        for job in jobs:
            jname = job["name"]
            jstatus = job["status"]
            jconclusion = job.get("conclusion", "?")
            steps = job.get("steps", [])
            print(f"  Job: {jname} [{jconclusion}]")
            for step in steps:
                sname = step["name"]
                sstatus = step["status"]
                sconclusion = step.get("conclusion", "?")
                if sconclusion != "success":
                    print(f"    - {sname}: [{sconclusion}]")
    else:
        print(f"  Jobs API: {rj.status_code}")
