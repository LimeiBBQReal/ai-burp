import os
import sys

sys.path.insert(0, r'E:\CursorDEV\CKFinder\ai-burp')
os.environ['PROXY_AES_KEY'] = 'ApOiDIzzSzdN6B4BGEWRjxfhGWU4I3o5'

import requests
from aiburp.proxy.proxy_pool_client import _aes_decrypt, AES_KEY

print(f'AES_KEY in env: {AES_KEY!r}')

for f in ['http.enc', 'socks5.enc', 'meta.enc']:
    url = f'https://raw.githubusercontent.com/LimeiBBQReal/proxy-pool/main/alive/{f}'
    r = requests.get(url, timeout=15)
    if r.status_code != 200:
        print(f'{f}: HTTP {r.status_code}')
        continue
    try:
        text = _aes_decrypt(r.content, AES_KEY)
        lines = text.strip().split('\n')
        print(f'{f}: decrypted OK, {len(lines)} lines')
        print(f'  preview: {lines[0] if lines else "(empty)"}')
        if len(lines) > 1:
            print(f'  ...: {lines[-1]}')
    except Exception as e:
        print(f'{f}: DECRYPT FAIL: {type(e).__name__}: {e}')