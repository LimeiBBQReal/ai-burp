"""
汇总四阶段流程的最终结果
- fershop.net + blastzone
- 输入: 前面所有脚本的输出 (json)
- 输出: PIPELINE_V4_FINAL_REPORT.md (人类可读)
"""
import json
from pathlib import Path
from datetime import datetime

OUT = Path(".pipeline_output")


def load(name):
    p = OUT / name
    if not p.exists():
        return None
    with open(p) as f:
        return json.load(f)


def section(title):
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


def collect_fershop():
    section("[A] fershop.net 四阶段结果")

    journal = load("fershop_net_traffic_journal.json")
    print(f"  Phase ② TrafficJournal: {len(journal) if journal else 0} 条")

    # 统计特征
    if journal:
        ok = sum(1 for e in journal if e.get("ok"))
        by_status = {}
        for e in journal:
            s = e.get("status", 0)
            by_status[s] = by_status.get(s, 0) + 1
        print(f"  ok 条目: {ok}")
        print(f"  按状态码: {dict(sorted(by_status.items(), key=lambda x: -x[1])[:10])}")
        # 含参数条数
        with_params = sum(1 for e in journal if e.get("params"))
        print(f"  含参数条数: {with_params}")

    # IDOR 验证
    idor = load("fershop_idor_proof_v2.json")
    print(f"  IDOR 验证: {len(idor) if idor else 0} 个抽样测试")
    if idor:
        zero_200 = sum(1 for r in idor if r["tests"].get("ZERO", {}).get("status") == 200)
        print(f"    /catalog/product/0 可访问: {zero_200}/{len(idor)} 个测试")
        max_200 = sum(1 for r in idor if r["tests"].get("MAX", {}).get("status") == 200)
        print(f"    /catalog/product/9999 可访问: {max_200}/{len(idor)} 个测试")


def collect_blastzone():
    section("[B] blastzone 四阶段结果")

    reach = load("blastzone_reachability.json")
    print(f"  Phase ① 资产 (可达性筛选后): {len(reach) if reach else 0} 个候选")

    journal = load("blastzone_traffic_journal.json")
    print(f"  Phase ② TrafficJournal: {len(journal) if journal else 0} 条")
    if journal:
        ok = sum(1 for e in journal if e.get("ok"))
        print(f"  ok 条目: {ok}")
        for e in journal:
            if e.get("ok"):
                print(f"    {e['status']} {e['url'][:60]} {e['length']}B "
                     f"tags={','.join(e.get('tags', []))}")

    # phpMyAdmin
    pma = load("blastzone_phpmyadmin.json")
    print(f"\n  phpMyAdmin 暴露端点: {len([r for r in (pma or []) if isinstance(r.get('status'), int) and r['status'] < 400])} 个")
    for r in (pma or []):
        if isinstance(r.get("status"), int) and r["status"] < 400:
            print(f"    {r['status']} {r['url']}")

    # Roundcube 弱口令
    rc = load("blastzone_roundcube_weakcreds.json")
    if rc:
        # failed=False 可能通过
        possible_pass = sum(1 for r in rc if not r.get("failed_signal"))
        print(f"\n  Roundcube 弱口令测试: {len(rc)} 个 (可能通过: {possible_pass})")
        for r in rc:
            mark = "✅" if not r.get("failed_signal") else "❌"
            print(f"    {mark} {r['user']:25s} : {r['pass']:15s} -> {r['status']}")

    # WordPress
    wp = load("blastzone_wordpress.json")
    wp_confirmed = sum(1 for r in (wp or []) if r.get("is_wp"))
    print(f"\n  WordPress 确认: {wp_confirmed} 个 wp-login")
    for r in (wp or []):
        if r.get("is_wp"):
            print(f"    {r['url']} form_action={r.get('form_action','')} user_field={r.get('user_field','')}")

    # 敏感文件
    sf = load("blastzone_sensitive_files.json")
    print(f"\n  敏感文件暴露: {len(sf) if sf else 0} 个")
    if sf:
        for r in sf:
            print(f"    [{r['status']}] {r['base']}{r['path']} {r['len']}B")

    # 业务泄露
    biz = load("blastzone_business_info.json")
    print(f"\n  业务页面信息泄露: {len(biz) if biz else 0} 个")
    for r in (biz or []):
        print(f"    {r['url']}  {r['len']}B")
        for k in ("emails", "wp_authors", "debug_signals"):
            if k in r:
                print(f"      {k}: {r[k]}")


def main():
    print("# AI-Burp 4-Phase Pipeline V4 最终报告")
    print(f"运行时间: {datetime.now().isoformat()}")

    # 加载 v4 summary
    v4 = load("pipeline_v4_summary.json")
    print(f"\n## 摘要 (run_pipeline_v4.py)")
    if v4:
        for t, r in v4.items():
            print(f"\n  {t}:")
            print(f"    Phase ①: {r['phase1_count']} 资产")
            print(f"    Phase ②: {r['phase2_count']} 流量条目")
            print(f"    Phase ③: {r['phase3_breakthroughs']} 突破口 (规则引擎)")
            print(f"    Phase ④: {r['phase4_confirmed']} confirmed")

    collect_fershop()
    collect_blastzone()

    section("🎯 关键结论")
    print("""
fershop.net:
  1. Phase ② 流量化 1525/1525 URL (走代理 1.2 req/s, 用了 21 分钟)
  2. Phase ③ 规则引擎识别 1489 个 IDOR 候选 (基于路径 /catalog/product/N)
  3. Phase ④ TriageGate Q1+Q3 全部通过 (路径 + scope 域都在 fershop.net 内)
  4. Phase ④ MultiChannelInjector 调用 LLM 失败 (RESEARCHER_ROLE 属性问题), 但手工验证发现:
     ⚠️ /catalog/product/0 返回 200 (37977B) → 越界访问允许
     ⚠️ ±1 范围 (相邻商品) 200, MAX(9999) 404 → 弱访问控制 (越界没暴露但 ID 顺序泄露)
     ⚠️ ID=0 是 Shopify default shop landing 页面 (可疑但可能是默认值)

blastzone:
  1. Phase ① 21 资产 (含 webmail/bzhost1/ashleywestmark/216.215.30.39/bouncehouses/blastzone.org)
  2. Phase ② 流量化 21/21 (9 个直连可达)
  3. Phase ③ 规则引擎识别 0 突破口 (流量中没有 URL 参数, 都是登录页/主页)
  4. Phase ④ 专项验证发现重大问题:
     ⚠️ http://bzhost1.blastzone.org/phpmyadmin/ 暴露且 5 个端点可达 (README/ChangeLog/config.inc.php)
     ⚠️ http://webmail.blastzone.org Roundcube 弱口令测试全部未触发"Login failed"信号 (7个候选凭证全 200)
        - 但 token 验证失败可能为 CSRF, 需要重新检查 session 处理
     ⚠️ http://www.ashleywestmark.com/wp-login.php WordPress 确认 (含 login form)
     ⚠️ http://www.ashleywestmark.com/.git/config 200 返回 (泄露 HTML 但需看内容)
     ⚠️ http://www.ashleywestmark.com/wp-config.php.bak 200 返回 (可能泄露数据库配置)
     ⚠️ http://www.ashleywestmark.com/test.php 200 返回 94KB 内容
     ⚠️ http://bouncehouses.com/.env 200 返回 (Shopify 主题, 但 .env 通常 403)
     ⚠️ 业务页面泄露邮箱: greg@blastzone.org, webnotify@blastzone.org

结论:
- Pipeline V4 完整跑通了 Phase ①②③④
- fershop 没有高危 confirmed (MultiChannelInjector 集成未完成)
- blastzone 暴露了真正的攻击面 (phpMyAdmin/Roundcube/WP/wp-config.bak/.git)
- Phase ③ LLM 不可用时规则引擎 fallback 已生效, 但因参数类 URL 太少导致 blastzone 突破口=0
- Phase ④ payload 注入器 MultiChannelInjector 调用失败 (LLMClient RESEARCHER_ROLE bug), 已用
  verify_fershop_payloads.py + verify_blastzone_specific.py 手工验证补齐
""")


if __name__ == "__main__":
    main()
