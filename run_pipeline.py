"""
Pipeline — 对 fershop.net 运行 CrawlerEngine + 资产采集 (直连版)
跳过不可达的 blastzone (bzhost1.com 返回 502)
"""
import sys, time, json, asyncio
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import requests
import urllib3
urllib3.disable_warnings()

OUT_DIR = Path(".pipeline_output")
OUT_DIR.mkdir(exist_ok=True)

def log(msg):
    t = time.strftime("%H:%M:%S")
    print(f"[{t}] {msg}")

# =============================================
# Phase 1: fershop.net — CrawlerEngine (直连)
# =============================================
async def run_fershop():
    log(f"\n{'='*60}")
    log("CrawlerEngine -> fershop.net (直连)")
    log(f"{'='*60}")

    from aiburp.crawler import CrawlerEngine

    dict_paths = []
    payload_dir = Path(__file__).parent / "payloads" / "discovery"
    for fname in ["dirs_quick.txt", "swagger_docs.txt", "api_endpoints.txt"]:
        fpath = payload_dir / fname
        if fpath.exists():
            with open(fpath, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("//"):
                        if not line.startswith("/"):
                            line = "/" + line
                        dict_paths.append(line)
    dict_paths = list(dict.fromkeys(dict_paths))
    # 加上报告已知路径
    for extra in ["/admin.php", "/api/delete_order", "/api/orders"]:
        if extra not in dict_paths:
            dict_paths.append(extra)
    log(f"字典: {len(dict_paths)} 条")

    session = requests.Session()
    session.verify = False
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    engine = CrawlerEngine(
        base_url="https://fershop.net",
        session=session,
        llm_client=None,
        max_depth=2,
        max_urls=200,
        dict_paths=dict_paths,
        concurrency=10,
        request_delay=0.1,
        proxy_manager=None,  # 直连
    )

    t0 = time.time()
    inv = await engine.run()
    elapsed = time.time() - t0
    log(f"耗时: {elapsed:.0f}s")

    from collections import Counter
    source_counts = Counter(item.source for item in inv.items)
    log(f"\n发现摘要 ({len(inv.items)} 总资产):")
    for src, cnt in source_counts.most_common():
        log(f"  {src}: {cnt}")

    urls_found = [item for item in inv.items if item.type == "url"]
    if urls_found:
        unique_urls = list(dict.fromkeys(item.value for item in urls_found))
        log(f"\nURL ({len(unique_urls)} 去重):")
        for url in unique_urls[:40]:
            log(f"  {url}")
        if len(unique_urls) > 40:
            log(f"  ... +{len(unique_urls)-40}")

        with open(OUT_DIR / "fershop_urls.txt", "w") as f:
            for url in unique_urls:
                f.write(f"{url}\n")
        log(f"URL 列表 -> .pipeline_output/fershop_urls.txt")

    with open(OUT_DIR / "fershop_inventory.json", "w") as f:
        json.dump([{
            "type": item.type, "value": item.value,
            "source": item.source, "confidence": item.confidence,
            "tags": item.tags, "metadata": item.metadata,
        } for item in inv.items], f, indent=2, ensure_ascii=False)
    log(f"Inventory -> .pipeline_output/fershop_inventory.json")

    # 非 sitemap 发现
    nonsitemap = [
        item for item in inv.items
        if item.source not in ("crawler_sitemap", "seed", "sitemap")
    ]
    if nonsitemap:
        log(f"\n非 sitemap 发现摘要 ({len(nonsitemap)}):")
        seen = set()
        for item in nonsitemap:
            if item.value not in seen:
                seen.add(item.value)
                log(f"  [{item.source}] {item.value}")
        with open(OUT_DIR / "fershop_nonsitemap.json", "w") as f:
            json.dump([{
                "type": item.type, "value": item.value,
                "source": item.source, "confidence": item.confidence,
                "tags": item.tags,
            } for item in nonsitemap], f, indent=2, ensure_ascii=False)
        log(f"非 sitemap 发现 -> .pipeline_output/fershop_nonsitemap.json")

    return inv


# =============================================
# Phase 2: 已知发现复查
# =============================================
def phase2_review():
    log(f"\n{'='*60}")
    log("已知发现复查 (直连)")
    log(f"{'='*60}")

    s = requests.Session()
    s.trust_env = False
    s.verify = False
    s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    checks = {
        "Admin Panel": "https://fershop.net/admin.php",
        "Delete Order API": "https://fershop.net/api/delete_order",
        "Orders API": "https://fershop.net/api/orders",
        "Login": "https://fershop.net/api/login",
        "User Profile": "https://fershop.net/api/user/profile",
        "S3 bucket": "https://s3.amazonaws.com/fershop-backup",
        "Google OAuth callback": "https://fershop.net/api/auth/google/callback",
        "Swagger": "https://fershop.net/api/docs",
        "Swagger JSON": "https://fershop.net/api/swagger.json",
    }

    results = []
    for name, url in checks.items():
        try:
            r = s.get(url, timeout=8, allow_redirects=False)
            status = r.status_code
            size = len(r.content)
            ct = r.headers.get("content-type", "")[:30]
            results.append((name, url, status, size, ct))
            log(f"  {name:25s} {status:3d} {size:>8}B {ct}")
        except Exception as e:
            log(f"  {name:25s} FAILED: {str(e)[:50]}")

    s.close()
    with open(OUT_DIR / "fershop_manual_checks.json", "w") as f:
        json.dump(results, f, ensure_ascii=False)
    log(f"手动检查 -> .pipeline_output/fershop_manual_checks.json")


async def main():
    log(f"{'='*50}")
    log("FERSHOP PIPELINE")
    log(f"{'='*50}")

    inv = await run_fershop()
    phase2_review()

    log(f"\n{'='*50}")
    log(f"Done! Output: {OUT_DIR}")
    log(f"{'='*50}")

if __name__ == "__main__":
    asyncio.run(main())
