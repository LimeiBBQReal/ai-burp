"""下载失败 workflow 的具体日志看原因."""
import requests, zipfile, io

TOKEN = "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"
OWNER = "LimeiBBQReal"
REPO = "ai-burp-recon"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

FAILED_RUNS = [
    ("DNS Enum", 28331823194),
    ("Port Scan", 28331824932),
    ("Banner Grab", 28331826266),
    ("Directory Brute", 28331827753),
    ("Hidden Params", 28331828995),
    ("CIDR Scan", 28331832024),
    ("URL Collect", 28331833270),
    ("Deep Subdomain", 28331835028),
]

for wf, rid in FAILED_RUNS:
    print(f"\n{'='*60}")
    print(f"WORKFLOW: {wf} (id={rid})")
    print(f"{'='*60}")
    
    log_url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/runs/{rid}/logs"
    r2 = requests.get(log_url, headers=HEADERS, timeout=60, stream=True)
    z = zipfile.ZipFile(io.BytesIO(r2.content))
    
    # 找 Run 步骤
    for name in sorted(z.namelist()):
        if "Run " in name and ".txt" in name and "actions" not in name and "pip install" not in name:
            content = z.read(name).decode("utf-8", errors="replace")
            lines = content.strip().split("\n")
            # 看最后 15 行
            last = "\n".join(lines[-15:])
            print(f"\n[{name}] (last 15 lines)")
            print(last[:800])
