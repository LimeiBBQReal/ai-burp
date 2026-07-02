#!/usr/bin/env python3
"""通过 GitHub API 触发 refresh workflow_dispatch, 然后轮询状态."""
import json
import subprocess
import sys
import time
from pathlib import Path

TOKEN = subprocess.run(
    ['git', 'credential', 'fill'],
    input=b'protocol=https\nhost=github.com\n\n',
    capture_output=True,
).stdout.decode()
token_line = [l for l in TOKEN.splitlines() if l.startswith('password=')][0]
TOKEN = token_line.split('=', 1)[1]
print(f"[+] token 取到 (长度 {len(TOKEN)})")

import urllib.request


def http(method: str, url: str, data: dict | None = None) -> tuple[int, dict]:
    headers = {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'Authorization': f'Bearer {TOKEN}',
        'User-Agent': 'manual-trigger',
    }
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return e.code, {'error': e.read().decode()[:300]}


# 1. 触发 workflow_dispatch
url = 'https://api.github.com/repos/LimeiBBQReal/proxy-pool/actions/workflows/refresh.yml/dispatches'
code, data = http('POST', url, {'ref': 'main', 'inputs': {'workers': '100'}})
print(f"[POST dispatch] {code} {data if code not in (201, 204) else ''}")
if code not in (201, 204):
    sys.exit(1)

# 2. 轮询最近 5 次 run, 找新触发的 (status=queued/in_progress)
run_url = 'https://api.github.com/repos/LimeiBBQReal/proxy-pool/actions/runs?per_page=5'
new_run = None
for i in range(30):
    time.sleep(4)
    code, data = http('GET', run_url)
    if code != 200:
        print(f"[GET runs] {code} {data}")
        continue
    runs = data.get('workflow_runs', [])
    for r in runs:
        if r.get('event') == 'workflow_dispatch' and r.get('status') in ('queued', 'in_progress'):
            new_run = r
            break
    if new_run:
        break
    print(f"[轮询 #{i+1}] 还没看到新 run, 列表前 3: {[r.get('event')+'/'+r.get('status') for r in runs[:3]]}")

if not new_run:
    print("[!] 60 秒内没看到新 run, 直接列前 5 个让用户判断")
    code, data = http('GET', run_url)
    for r in data.get('workflow_runs', []):
        print(f"  {r.get('id')} {r.get('event')} {r.get('status')} {r.get('conclusion')} {r.get('display_title')}")
    sys.exit(2)

print(f"[+] 新 run 触发成功: id={new_run['id']} html={new_run['html_url']}")

# 3. 轮询直到完成
status_url = f"https://api.github.com/repos/LimeiBBQReal/proxy-pool/actions/runs/{new_run['id']}"
for i in range(60):  # 最多 10 分钟
    time.sleep(10)
    code, data = http('GET', status_url)
    if code != 200:
        print(f"[GET run] {code} {data}")
        continue
    s = data.get('status')
    c = data.get('conclusion')
    print(f"[轮询 #{i+1}] status={s}  conclusion={c}  url={data.get('html_url')}")
    if s == 'completed':
        if c == 'success':
            print("[+] 完成, 成功")
            sys.exit(0)
        else:
            print(f"[!] 完成, 但是结论 = {c}")
            sys.exit(3)

print("[!] 10 分钟还没跑完, 超时")
sys.exit(4)
