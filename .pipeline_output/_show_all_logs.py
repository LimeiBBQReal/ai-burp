"""下载最新的 subdomain run (c2e1d93) 日志检查 commit 步骤的问题."""
import requests, zipfile, io

TOKEN = "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"
OWNER = "LimeiBBQReal"
REPO = "ai-burp-recon"
RUN_ID = 28331693625

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/runs/{RUN_ID}/logs"
r = requests.get(url, headers=HEADERS, timeout=60, stream=True)

z = zipfile.ZipFile(io.BytesIO(r.content))

for name in z.namelist():
    content = z.read(name).decode("utf-8", errors="replace")
    print(f"\n{'='*60}")
    print(f"FILE: {name}")
    print(f"{'='*60}")
    print(content)
