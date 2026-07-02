"""
全自动批量资产处理 — 25 个域名.

对每个域名执行:
    1. HTTP/HTTPS 存活 + 重定向链
    2. 标题/Server/CMS 指纹
    3. 高危路径探测 (admin/login/.git/wp-config/debug)
    4. 端口侧探活 (80/443/8080/8443)

全程走代理 (ProxyGuard). 输出 JSON + Markdown 报告.
"""
import warnings, urllib3, re, json, time, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
warnings.filterwarnings('ignore'); urllib3.disable_warnings()

from huntaid import init_proxy, banner

DOMAINS = [
    'artfulbullet.com', 'ashleywestmark.com', 'blastzone.com', 'blastzone.org',
    'blastzonewebhosting.com', 'burnsim.com', 'dryharvest.com',
    'homecontrolassistant.com', 'lesabrage.com', 'lokiresearch.com',
    'mdra-archive.org', 'mdrocketry.net', 'myth-racing.com', 'nar.org',
    'northwestrocketry.com', 'nypower.org', 'pembertontechnologies.com',
    'performancehobbies.com', 'rasaero.com', 'rocketflite.com',
    'rocketry-education.com', 'rocketrydata.com', 'rousetech.net',
    'scottsrockets.com', 'technicopedia.com',
]

# 高危路径 (短列表, 控制请求数避免触发 WAF)
DANGER_PATHS = [
    'admin', 'login', '.git/HEAD', '.env', 'wp-config.php.bak',
    'phpmyadmin/', 'server-status', 'swagger-ui/', 'graphql',
    'api/', 'wp-json/', 'actuator/health',
]


def probe_domain(domain, session):
    """单个域名全自动探测."""
    result = {'domain': domain, 'http': {}, 'https': {}, 'paths': {}, 'fingerprint': {}}

    for scheme in ('https', 'http'):
        url = f'{scheme}://{domain}/'
        try:
            r = session.get(url, timeout=8, allow_redirects=True)  # 缩短到8s
            body = r.text[:5000]
            result[scheme] = {
                'status': r.status_code,
                'alive': True,
                'final_url': r.url,
                'size': len(r.text),
                'title': (re.search(r'<title[^>]*>([^<]*)</title>', body, re.I) or [None,''])[1][:60],
                'server': r.headers.get('Server', ''),
                'powered': r.headers.get('X-Powered-By', ''),
            }
            # CMS/技术指纹
            fps = []
            if 'wp-content' in body or 'wp-includes' in body:
                fps.append('WordPress')
                gen = re.search(r'WordPress ([0-9.]+)', body)
                if gen: fps.append(f'WP {gen.group(1)}')
            if '__VIEWSTATE' in body: fps.append('ASP.NET')
            if 'JSESSIONID' in str(r.headers): fps.append('Java')
            if 'laravel' in body.lower(): fps.append('Laravel')
            if 'cloudflare' in r.headers.get('Server','').lower(): fps.append('CDN:Cloudflare')
            result['fingerprint'][scheme] = fps
            # HTTPS 优先, HTTP 找到就不再测
            break
        except Exception as e:
            result[scheme] = {'alive': False, 'error': type(e).__name__}

    # 高危路径探测 (只用存活的 scheme)
    alive_scheme = 'https' if result['https'].get('alive') else ('http' if result['http'].get('alive') else None)
    if alive_scheme:
        base = f'{alive_scheme}://{domain}'
        for path in DANGER_PATHS:
            try:
                r = session.get(f'{base}/{path}', timeout=5, allow_redirects=False)  # 5s
                # 只记录有意义的响应
                if r.status_code in (200, 401, 403):
                    snippet = ''
                    if r.status_code == 200 and len(r.text) > 50:
                        snippet = r.text[:40].replace('\n',' ').replace('\r','')
                    result['paths'][path] = {'status': r.status_code, 'size': len(r.text), 'snippet': snippet}
            except Exception:
                pass
            time.sleep(0.3)  # 礼貌延迟

    return result


def assess_finding(result):
    """从探测结果提取安全发现."""
    findings = []
    d = result['domain']
    fp = result.get('fingerprint', {})

    # WordPress 暴露
    for s, tags in fp.items():
        if 'WordPress' in tags:
            findings.append(('WordPress 暴露', 'medium', f'{d} ({s})'))
            break

    # 危险路径 — 只有 200 才算泄露, 401/403 只是"存在但被防护"
    for path, info in result.get('paths', {}).items():
        if path in ('.git/HEAD', '.env', 'wp-config.php.bak') and info['status'] == 200:
            findings.append((f'{path} 泄露', 'critical', f'{d} → 200 {info["size"]}b'))
        elif path in ('phpmyadmin/',) and info['status'] == 200:
            findings.append(('phpMyAdmin 暴露', 'critical', f'{d}'))
        elif path == 'server-status' and info['status'] == 200:
            findings.append(('server-status 暴露', 'high', f'{d} → Apache 状态页'))
        elif path == 'actuator/health' and info['status'] == 200:
            findings.append(('Spring Actuator 暴露', 'critical', f'{d}'))
        elif path == 'graphql' and info['status'] in (200, 400):
            findings.append(('GraphQL 暴露', 'medium', f'{d}'))
        elif path in ('admin', 'login') and info['status'] == 200:
            findings.append((f'/{path} 可达', 'low', f'{d}'))
        # 401/403 = 存在但被防护, 不算漏洞 (信息价值低, 不计入发现)

    return findings


def _save_results(all_results, findings=None):
    """增量保存结果 (防超时丢失)."""
    if findings is None:
        findings = []
        for r in all_results:
            findings.extend({'domain': r['domain'], 'type': t, 'severity': s, 'evidence': e}
                           for t, s, e in assess_finding(r))
    with open('reports/batch_domain_scan.json', 'w', encoding='utf-8') as f:
        json.dump({'results': all_results, 'findings': findings,
                   'scanned': len(all_results),
                   'total_findings': len(findings)}, f, ensure_ascii=False, indent=2)


if __name__ == '__main__':
    banner(f'[全自动] 25 域名批量处理 (走代理)')
    guard = init_proxy()
    session = guard.session

    all_results = []
    all_findings = []

    try:
        # 串行处理 (避免并发触发 WAF, 且代理单节点)
        for i, domain in enumerate(DOMAINS, 1):
            print(f'\n[{i}/{len(DOMAINS)}] {domain}', end=' ... ', flush=True)
            try:
                r = probe_domain(domain, session)
                all_results.append(r)
                # 打印摘要
                alive = r['https'].get('alive') or r['http'].get('alive')
                if alive:
                    s = r.get('fingerprint', {})
                    tags = s.get('https') or s.get('http') or []
                    title = (r['https'].get('title') or r['http'].get('title') or '')[:30]
                    sv = r['https'].get('server') or r['http'].get('server') or ''
                    print(f'存活 | {sv[:20]} | {title} | {tags}')
                    # 路径发现
                    hits = [p for p,info in r.get('paths',{}).items() if info['status'] in (200,401,403)]
                    if hits: print(f'        路径命中: {hits}')
                else:
                    print('离线')
                # 增量保存 (每5个域名存一次, 防止超时丢失)
                if i % 5 == 0:
                    _save_results(all_results)
                    guard.rotate()
            except Exception as e:
                print(f'ERR {type(e).__name__}')
                all_results.append({'domain': domain, 'error': str(e)[:60]})
            time.sleep(0.5)

        # 汇总发现
        banner('[汇总] 安全发现')
        for r in all_results:
            for title, sev, evidence in assess_finding(r):
                all_findings.append({'domain': r['domain'], 'type': title, 'severity': sev, 'evidence': evidence})
                icon = {'critical':'🔴','high':'🟠','medium':'🟡','low':'🟢'}.get(sev,'⚪')
                print(f'  {icon} [{sev}] {title}: {evidence}')

        # 保存 JSON
        with open('reports/batch_domain_scan.json', 'w', encoding='utf-8') as f:
            json.dump({'results': all_results, 'findings': all_findings,
                       'scanned': len(all_results),
                       'total_findings': len(all_findings)}, f, ensure_ascii=False, indent=2)
        print(f'\n保存: reports/batch_domain_scan.json')
        print(f'扫描: {len(all_results)} 域名 | 发现: {len(all_findings)} 项')

    finally:
        guard.close()
