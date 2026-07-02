"""下载所有 workflow 的完整日志找失败原因 (d860cb24 版本)."""
import requests, zipfile, io

TOKEN = "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"
OWNER = "LimeiBBQReal"
REPO = "ai-burp-recon"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

FAILED_RUNS = {}

# Get latest runs
url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/runs?per_page=20&status=completed&event=workflow_dispatch"
r = requests.get(url, headers=HEADERS, timeout=15)
runs = r.json().get("workflow_runs", [])

for run in runs:
    if run["head_sha"].startswith("d860cb2") and run.get("conclusion") == "failure":
        FAILED_RUNS[run["name"]] = run["id"]

print(f"找到 {len(FAILED_RUNS)} 个失败 run:\n")

for wf, rid in FAILED_RUNS.items():
    print(f"\n{'='*60}")
    print(f"WORKFLOW: {wf} (id={rid})")
    print(f"{'='*60}")
    
    log_url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/runs/{rid}/logs"
    r2 = requests.get(log_url, headers=HEADERS, timeout=60, stream=True)
    z = zipfile.ZipFile(io.BytesIO(r2.content))
    
    for name in sorted(z.namelist()):
        content = z.read(name).decode("utf-8", errors="replace")
        # 找 error 或 exit code
        if "error" in content.lower() or "exit code" in content.lower() or "fatal" in content.lower() or "traceback" in content.lower():
            lines = content.strip().split("\n")
            # 拿最后 10 行
            last = "\n".join(lines[-10:])
            print(f"\n[{name}]")
            print(last[:500])
            break
    else:
        # 没有错误信息，看最后的 Run 步骤
        for name in sorted(z.namelist()):
            if "Run " in name and ".txt" in name:
                content = z.read(name).decode("utf-8", errors="replace")
                lines = content.strip().split("\n")
                last = "\n".join(lines[-5:])
                print(f"\n[{name}] (last 5 lines)")
                print(last[:500])
                break
