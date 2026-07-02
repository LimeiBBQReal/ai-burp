"""
Sitemap / Robots.txt Parser
纯正则解析，零依赖
"""

import re
from typing import List
from urllib.parse import urljoin


_SITEMAP_URL_PAT = re.compile(
    r'<loc>\s*(.*?)\s*</loc>',
    re.IGNORECASE | re.DOTALL,
)

_SITEMAP_INDEX_PAT = re.compile(
    r'<sitemap>\s*<loc>\s*(.*?)\s*</loc>',
    re.IGNORECASE | re.DOTALL,
)

_ROBOTS_SITEMAP_PAT = re.compile(
    r'^\s*Sitemap:\s*(\S+)',
    re.IGNORECASE | re.MULTILINE,
)

_ROBOTS_DISALLOW_PAT = re.compile(
    r'^\s*Disallow:\s*(\S+)',
    re.IGNORECASE | re.MULTILINE,
)

_ROBOTS_ALLOW_PAT = re.compile(
    r'^\s*Allow:\s*(\S+)',
    re.IGNORECASE | re.MULTILINE,
)

_ROBOTS_CRAWL_DELAY_PAT = re.compile(
    r'^\s*Crawl-Delay:\s*(\d+)',
    re.IGNORECASE | re.MULTILINE,
)


def parse_sitemap(xml_content: str, base_url: str = '') -> List[str]:
    urls = []

    # sitemap index 递归
    index_sitemaps = _SITEMAP_INDEX_PAT.findall(xml_content)
    for sitemap_url in index_sitemaps:
        sitemap_url = sitemap_url.strip()
        if sitemap_url:
            urls.append(urljoin(base_url, sitemap_url))

    url_tags = _SITEMAP_URL_PAT.findall(xml_content)
    for loc in url_tags:
        loc = loc.strip()
        if loc:
            urls.append(urljoin(base_url, loc))

    return urls


def parse_robots(txt_content: str, base_url: str = '') -> dict:
    sitemaps = [
        urljoin(base_url, m.group(1).strip())
        for m in _ROBOTS_SITEMAP_PAT.finditer(txt_content)
        if m.group(1).strip()
    ]

    disallowed = [
        m.group(1).strip()
        for m in _ROBOTS_DISALLOW_PAT.finditer(txt_content)
        if m.group(1).strip()
    ]

    allowed = [
        m.group(1).strip()
        for m in _ROBOTS_ALLOW_PAT.finditer(txt_content)
        if m.group(1).strip()
    ]

    delays = [
        int(m.group(1))
        for m in _ROBOTS_CRAWL_DELAY_PAT.finditer(txt_content)
    ]

    return {
        'sitemaps': sitemaps,
        'disallow': disallowed,
        'allow': allowed,
        'crawl_delay': delays[0] if delays else None,
    }
