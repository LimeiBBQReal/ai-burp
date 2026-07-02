"""
aiburp/deep_mining/active_probe.py
主动探查 — robots.txt / sitemap.xml / .well-known/security.txt / 常见 API 路径.

策略:
  - 一次性并发探测
  - 优先复用 crawler.sitemap 解析
  - 探到的新 URL 直接作为 Phase ① 的补充资产
"""
import asyncio
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse


WELL_KNOWN_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/favicon.ico",
    "/api",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/admin",
    "/login",
    "/health",
    "/healthz",
    "/status",
    "/server-status",
    "/.git/HEAD",
    "/.env",
    "/wp-login.php",
    "/phpmyadmin/",
    "/xmlrpc.php",
]


async def probe_one(session, url: str, timeout: float = 8.0) -> Dict:
    """单 URL 探查, 返回 status / length / content_type / body_preview."""
    try:
        r = await asyncio.get_running_loop().run_in_executor(
            None, lambda: session.get(url, timeout=timeout,
                                      allow_redirects=True)
        )
        body = r.text[:500] if r.status_code == 200 else ""
        return {
            "url": url,
            "status": r.status_code,
            "length": len(r.content),
            "content_type": r.headers.get("Content-Type", ""),
            "body_preview": body,
        }
    except Exception as e:
        return {"url": url, "status": 0, "error": str(e)[:60]}


async def probe_active(session, base_url: str,
                       paths: Optional[List[str]] = None,
                       concurrency: int = 5) -> Dict:
    """
    并发探查常见路径, 返回:
    {
      "results": [{url, status, length, content_type, body_preview}, ...],
      "discovered_urls": [...],  # 从 robots/sitemap 里解析出的新 URL
    }
    """
    base_url = base_url.rstrip("/")
    paths = paths or WELL_KNOWN_PATHS
    urls = [urljoin(base_url + "/", p.lstrip("/")) for p in paths]

    sem = asyncio.Semaphore(concurrency)

    async def _task(u: str) -> Dict:
        async with sem:
            return await probe_one(session, u)

    results = await asyncio.gather(*[_task(u) for u in urls])

    discovered = []
    for r in results:
        if r.get("status") == 200 and "body_preview" in r:
            body = r["body_preview"]
            url = r["url"]
            try:
                from aiburp.crawler.extractors.sitemap import parse_robots, parse_sitemap
                if url.endswith("/robots.txt"):
                    parsed = parse_robots(body, url)
                    discovered.extend(parsed.get("sitemaps", []))
                    discovered.extend([urljoin(url, d) for d in parsed.get("disallow", [])])
                elif "sitemap" in url and ("xml" in r.get("content_type", "").lower() or body.lstrip().startswith("<?xml")):
                    discovered.extend(parse_sitemap(body, url))
            except Exception:
                pass

    return {
        "results": results,
        "discovered_urls": list(set(discovered)),
    }


def probe_active_sync(session, base_url: str,
                      paths: Optional[List[str]] = None) -> Dict:
    """同步入口, 给 phase2 调用."""
    try:
        loop = asyncio.get_running_loop()
        return loop.run_until_complete(
            asyncio.gather(probe_active(session, base_url, paths))
        )[0]
    except RuntimeError:
        return asyncio.run(probe_active(session, base_url, paths))