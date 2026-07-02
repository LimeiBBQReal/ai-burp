#!/usr/bin/env python3
"""轮询单次 run 状态, 简短版."""
import json
import subprocess
import sys
import time
import urllib.request

run_id = sys.argv[1] if len(sys.argv) > 1 else '28290479767'
TOKEN = subprocess.run(
    ['git', 'credential', 'fill'],
    input=b'protocol=https\nhost=github.com\n\n',
    capture_output=True,
).stdout.decode()
TOKEN = [l for l in TOKEN.splitlines() if l.startswith('password=')][0].split('=', 1)[1]

url = f'https://api.github.com/repos/LimeiBBQReal/proxy-pool/actions/runs/{run_id}'
req = urllib.request.Request(url, headers={
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'Authorization': f'Bearer {TOKEN}',
    'User-Agent': 'poll',
})
for i in range(40):
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.loads(r.read())
        s = d.get('status')
        c = d.get('conclusion')
        print(f"[{i+1}] {s} / {c}  url={d.get('html_url')}")
        if s == 'completed':
            print(f"FINAL: conclusion={c}")
            sys.exit(0 if c == 'success' else 1)
    except Exception as e:
        print(f"[{i+1}] err: {e}")
    time.sleep(15)
print("TIMEOUT")
sys.exit(2)
