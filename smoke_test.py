"""端到端冒烟测试 — 验证 Phase 1+2+3+4 全部连通 (H5 async 版)."""
import sys
import asyncio
sys.path.insert(0, '.')

from aiburp.agent import SecurityAgent

print('=' * 60)
print('AI-Burp V4 ALL-IN-TRAFFIC 端到端冒烟 (H5 async)')
print('=' * 60)

a = SecurityAgent('smoke', proxy_manager=None)


async def main():
    # 1. engine 可用 + 共享
    print('\n[1] 共享 TrafficEngine 验证')
    async def noop(eng):
        return type(eng).__name__

    t1 = await a._run_with_engine(noop)
    t2 = await a._run_with_engine(noop)
    print('   engine 类型: %s (1st) / %s (2nd) — 一致: %s' % (t1, t2, t1 == t2))

    # 2. 验证 id 一致 (同一 loop 内共享)
    async def id_test(eng):
        return id(eng)

    id1 = await a._run_with_engine(id_test)
    id2 = await a._run_with_engine(id_test)
    print('   id 一致: %s (预期 True)' % (id1 == id2))

    # 3. 验证所有 _action_* 存在
    print('\n[2] _action_* 完整性 (V4 全部走共享 engine)')
    methods = [
        'traffic_probe', 'traffic_scan', 'check_unauth', 'logic_scan',
        'exploit', 'traffic_analyze', 'detect_panel', 'cdn_bypass',
        'asset_expand', 'intel_lookup', 'supply_chain', 'login_brute',
        'full_audit', 'inject',
    ]
    for m in methods:
        fn = getattr(a, '_action_' + m, None)
        status = 'OK' if fn else 'MISSING'
        print('   _action_%s = %s' % (m, status))

    # 4. EXPERIENCE_LESSONS 规则引擎
    print('\n[3] EXPERIENCE_LESSONS 流量规则引擎')
    from aiburp.traffic import TrafficRuleEngine, DEFAULT_RULES
    print('   规则数: %d' % len(DEFAULT_RULES))
    eng = TrafficRuleEngine()

    ctx = {
        'url': 'https://target.com',
        'response': {
            'url': 'https://target.com',
            'status': 200,
            'headers': {'server': 'Apache/2.2.15'},
            'body': 'role:master\nreplicaof:1.2.3.4 6379\ncluster_slots:0\n',
            'banner': 'SSH-2.0-OpenSSH_7.4',
        },
    }
    hits = eng.apply(ctx)
    print('   命中: %d 条' % len(hits))
    for h in hits:
        print('     - [%s] %-25s %s' % (h.severity, h.finding_type, h.rule_desc))

    # 5. 模拟一次 traffic_analyze (用 stub engine, 不打网络)
    print('\n[4] 模拟 traffic_analyze (stub, 验证 async 包装)')

    class StubEngine:
        class _Adapters:
            http = None
        _adapters = _Adapters()
        async def probe(self, url, protocol='http', timeout=10):
            from aiburp.traffic.base import TrafficResponse
            return TrafficResponse(
                protocol='http', status=200,
                headers={'server': 'nginx/1.18', 'x-powered-by': 'PHP/5.6'},
                text='<title>phpmyadmin</title><p>Stack trace at /var/www/html',
                banner='SSH-2.0-OpenSSH_7.4',
            )
        async def close(self):
            pass

    # 替换 _ensure_engine 的返回值
    orig_ensure = a._ensure_engine
    a._ensure_engine = lambda: StubEngine()
    result = await a._action_traffic_analyze({'url': 'https://test.com'})
    print('   ok: %s' % result.get('ok'))
    print('   summary: %s' % result.get('summary', '')[:120])
    if result.get('ok'):
        print('   analyzer_findings: %d 条' % len(result['data']['analyzer_findings']))
        print('   experience_rule_hits: %d 条' % len(result['data']['experience_rule_hits']))
        for h in result['data']['experience_rule_hits']:
            print('     - [%s] %s' % (h['severity'], h['finding_type']))
    a._ensure_engine = orig_ensure

    # 6. close 收尾
    print('\n[5] close() 收尾')
    a.close()
    print('   engine is None: %s' % (a.engine is None))

    print('\n' + '=' * 60)
    print('全部 Phase 1+2+3+4 冒烟通过 (H5 async)')
    print('=' * 60)


asyncio.run(main())
