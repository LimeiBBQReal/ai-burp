"""H5 端到端调试 — 用 harvested 代理跑 V4 pipeline."""
import sys
import os
sys.path.insert(0, '.')
print('[DEBUG] Python:', sys.version)
print('[DEBUG] cwd:', os.getcwd())

# 加载 .env
from pathlib import Path
env_path = Path('.env')
if env_path.exists():
    print('[DEBUG] 加载 .env...')
    for line in env_path.read_text().splitlines():
        s = line.strip()
        if s and not s.startswith('#') and '=' in s:
            k, _, v = s.partition('=')
            os.environ.setdefault(k.strip(), v.strip())

print('[DEBUG] 导入 SecurityAgent...')
from aiburp.agent import SecurityAgent
print('[DEBUG] 导入 ProxyManager...')
from aiburp.proxy_manager import ProxyManager
print('[DEBUG] 导入完成')

# 1. 设置 ProxyManager
print('[DEBUG] 加载代理池...')
pm = ProxyManager(auto_harvest=False)
yaml_path = 'aiburp/proxy/yaml/proxy_alive.yaml'
pm.load_from_yaml(yaml_path)
stats = pm.stats()
print('[DEBUG] 代理池: mode=%s total=%d alive=%d' % (
    stats['mode'], stats['total'], stats['alive']))

# 不做批量健康检查 — harvester 刚刚验证过, 且避免 httpbin.org 限流
# verify_proxy() 会在 run() 内逐一测试

# 预获取真实 IP (使用 ipify 避免 httpbin 限流)
print('[DEBUG] 预获取真实 IP...')
import requests as _r
_s = _r.Session()
_s.trust_env = False
_s.verify = False
_real_ip = ''
for _ip_url in ['https://api.ipify.org?format=json', 'https://ipapi.co/json/', 'https://httpbin.org/ip']:
    try:
        _resp = _s.get(_ip_url, timeout=10)
        if _resp.status_code == 200:
            if 'ipify' in _ip_url:
                _real_ip = _resp.json().get('ip', '')
            elif 'ipapi' in _ip_url:
                _real_ip = _resp.json().get('ip', '')
            else:
                _real_ip = _resp.json().get('origin', '').split(',')[0].strip()
            if _real_ip:
                break
    except:
        continue
print('[DEBUG] 真实 IP: %s' % (_real_ip or '获取失败'))
_s.close()

# 2. 创建 Agent
print('\n[DEBUG] 创建 SecurityAgent...')
agent = SecurityAgent('h5_debug', proxy_manager=pm)

# 3. 运行 (OpSec 闸门会自动验证代理)
print('\n[DEBUG] 启动 Agent (target=fershop.net)...')
result = agent.run(initial_instruction='fershop.net')

print('\n' + '=' * 60)
print('[DEBUG] 最终结果:')
print('  ok:', result.get('ok'))
print('  error:', result.get('error', '无')[:200])
if result.get('iterations'):
    print('  iterations:', result.get('iterations'))
if result.get('findings'):
    print('  findings:', len(result.get('findings', [])))
print('=' * 60)
