"""快速测试代理连通性"""
import sys, os
sys.path.insert(0, '.')
import yaml, requests
from pathlib import Path
import urllib3; urllib3.disable_warnings()

p = Path('aiburp/proxy/yaml/proxy_alive.yaml')
data = yaml.safe_load(p.read_text())
proxies = data.get('proxies', [])
print(f'YAML 中代理总数: {len(proxies)}')

alive = 0
test_urls = ['http://httpbin.org/ip', 'https://ipapi.co/json/']
for i, pr in enumerate(proxies):
    url = f'{pr["type"]}://{pr["server"]}:{pr["port"]}'
    ok = False
    for tu in test_urls:
        try:
            r = requests.get(tu, proxies={'http': url, 'https': url}, timeout=5, verify=False)
            if r.status_code == 200:
                ok = True
                break
        except:
            continue
    if ok:
        alive += 1
        if alive <= 10:
            print(f'  [OK] {pr["server"]}:{pr["port"]}')
    else:
        if i <= 5 or alive == 0:
            print(f'  [DEAD] {pr["server"]}:{pr["port"]}')

print(f'\n存活: {alive}/{len(proxies)}')
