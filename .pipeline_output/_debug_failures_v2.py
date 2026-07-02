"""下载所有失败 workflow 的最后部分日志 (d860cb24 版本)."""
import requests, zipfile, io

TOKEN = "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"
OWNER = "LimeiBBQReal"
REPO = "ai-burp-recon"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

# 获取最新的 failure runs (d860cb24 版本)
url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/runs?per_page=20&status=completed&event=workflow_dispatch"
r = requests.get(url, headers=HEADERS, timeout=15)
runs = r.json().get("workflow_runs", [])

# 按 commit 分组，找 d860cb24 版本的
for run in runs:
    if run["head_sha"].startswith("d860cb2"):
        rid = run["id"]
        wf = run["name"]
        conclusion = run.get("conclusion", "?")
        print(f"\n{'='*60}")
        print(f"WORKFLOW: {wf} [{conclusion}] (id={rid})")
        print(f"{'='*60}")
        
        # Download logs
        log_url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/runs/{rid}/logs"
        r2 = requests.get(log_url, headers=HEADERS, timeout=60, stream=True)
        z = zipfile.ZipFile(io.BytesIO(r2.content))
        
        for name in sorted(z.namelist()):
            if "Run " in name and ".txt" in name and "Post" not in name and "Complete" not in name:
                content = z.read(name).decode("utf-8", errors="replace")
                lines = content.strip().split("\n")
                # 拿最后 20 行
                last = "\n".join(lines[-20:]) if len(lines) > 20 else content
                print(f"\n[{name}]")
                print(last[:800])
                print()
