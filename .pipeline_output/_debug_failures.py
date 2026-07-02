"""下载所有失败的 workflow 日志, 找失败原因."""
import requests, zipfile, io, json

TOKEN = "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"
OWNER = "LimeiBBQReal"
REPO = "ai-burp-recon"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

FAILED_RUNS = {
    "dns": 28331823194,
    "portscan": 28331824932,
    "banner": 28331826266,
    "dir_brute": 28331827753,
    "params": 28331828995,
    "cidr": 28331832024,
    "urls": 28331833270,
    "deep": 28331835028,
}

def get_run_logs(run_id):
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/runs/{run_id}/logs"
    r = requests.get(url, headers=HEADERS, timeout=60, stream=True)
    z = zipfile.ZipFile(io.BytesIO(r.content))
    # 找 Run script 和 Commit results
    for name in sorted(z.namelist()):
        if "Run " in name and ".txt" in name and "Post" not in name and "Complete" not in name:
            yield name, z.read(name).decode("utf-8", errors="replace")

for name, run_id in FAILED_RUNS.items():
    print(f"\n{'='*60}")
    print(f"WORKFLOW: {name} (id={run_id})")
    print(f"{'='*60}")
    for log_name, content in get_run_logs(run_id):
        # 只取最后 30 行
        lines = content.strip().split("\n")
        last_lines = "\n".join(lines[-30:])
        print(f"[{log_name}]")
        print(last_lines[:1000])
