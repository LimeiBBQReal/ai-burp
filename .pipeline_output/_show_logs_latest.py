"""下载最新的 subdomain run (412c6ef) 的 Commit results 步骤日志."""
import requests, zipfile, io

TOKEN = "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"
OWNER = "LimeiBBQReal"
REPO = "ai-burp-recon"
RUN_ID = 28331609277  # latest subdomain with commit=412c6ef

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/runs/{RUN_ID}/logs"
r = requests.get(url, headers=HEADERS, timeout=60, stream=True)

z = zipfile.ZipFile(io.BytesIO(r.content))

targets = [
    "enum/5_Run subdomain enum.txt",
    "enum/6_Commit results.txt",
]

for name in z.namelist():
    if name in targets:
        content = z.read(name).decode("utf-8", errors="replace")
        print(f"\n{'='*60}")
        print(f"FILE: {name}")
        print(f"{'='*60}")
        print(content)
