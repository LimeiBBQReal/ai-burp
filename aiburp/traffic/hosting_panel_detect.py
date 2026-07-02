"""
主机面板指纹识别 — 检测 WHM/cPanel/Plesk/DirectAdmin 等共享主机管理面板.

对共享主机服务商 (如 blastzonewebhosting.com), 找到管理后台面板是关键突破步骤.
本模块可以:

    1. 并行探测常见面板路径
    2. 指纹识别面板类型和版本
    3. 已知默认凭据试探 (cPanel: root/cpanel, Plesk: admin/plesk...)

用法:
    import requests
    s = requests.Session()
    s.proxies = {'http': 'socks5h://127.0.0.1:7890'}

    detect = HostingPanelDetect(s)
    results = await detect.detect("https://blastzonewebhosting.com")
    for panel in results:
        print(f"发现 {panel.panel_type} v{panel.version} @ {panel.login_url}")
"""

import asyncio
import re
import time
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


# ============================================================
# 面板指纹库
# ============================================================

@dataclass
class PanelInfo:
    """检测到的面板信息."""
    panel_type: str = ""         # cpanel, whm, plesk, directadmin, ...
    version: str = ""
    login_url: str = ""
    server_software: str = ""
    detect_method: str = ""      # path, body_keyword, header, redirect
    confidence: float = 0.0      # 0.0 ~ 1.0
    default_creds: List[Tuple[str, str]] = field(default_factory=list)


@dataclass
class PanelDetectResult:
    """面板检测汇总结果."""
    base_url: str = ""
    panels: List[PanelInfo] = field(default_factory=list)
    total_checked: int = 0
    total_time_sec: float = 0.0
    error: str = ""


# 面板指纹定义: (面板类型, 路径, 响应关键词, 权重)
PANEL_FINGERPRINTS = [
    # cPanel / WHM
    {
        "type": "whm",
        "paths": ["/whm/", "/whm", "/cpsess*/", "/login/?login_only=1"],
        "keywords": ["WHM", "cPanel L.L.C.", "cpsess", "webhostmanager",
                    "WHM Login", "Server Information"],
        "default_creds": [("root", "cpanel"), ("root", "whm")],
    },
    {
        "type": "cpanel",
        "paths": ["/cpanel/", "/cpanel", "/webmail/", "/webmail"],
        "keywords": ["cPanel", "cpapi2", "Webmail", "Roundcube",
                    "Horde", "SquirrelMail", "paper_lantern"],
        "default_creds": [("root", "cpanel")],
    },
    # Plesk
    {
        "type": "plesk",
        "paths": ["/plesk/", "/plesk", "/admin/plesk/", ":8443/"],
        "keywords": ["Plesk", "plesk", "Odin", "Parallels Panel",
                    "Parallels Plesk", "WebPro Edition"],
        "port_hints": [8443],
        "default_creds": [("admin", "plesk"), ("admin", "setup")],
    },
    # DirectAdmin
    {
        "type": "directadmin",
        "paths": ["/directadmin/", "/:2222/", "/DA/"],
        "keywords": ["DirectAdmin", "directadmin", "DirectAdmin Login"],
        "port_hints": [2222],
        "default_creds": [("admin", "admin"), ("admin", "directadmin")],
    },
    # ISPConfig
    {
        "type": "ispconfig",
        "paths": ["/ispconfig/", "/ispconfig", "/admin/ispconfig/"],
        "keywords": ["ISPConfig", "ispconfig", "ISPConfig Login",
                    "WASD", "Panel"],
        "default_creds": [("admin", "ispconfig"), ("admin", "admin")],
    },
    # VestaCP / HestiaCP
    {
        "type": "vestacp",
        "paths": ["/vesta/", "/vestacp/", "/login/", "/:8083/"],
        "keywords": ["Vesta", "VestaCP", "Vesta Control Panel",
                    "hestia", "HestiaCP"],
        "port_hints": [8083],
        "default_creds": [("admin", "vesta")],
    },
    # CyberPanel
    {
        "type": "cyberpanel",
        "paths": ["/cyberpanel/", "/cyberpanel", "/panel/"],
        "keywords": ["CyberPanel", "cyberpanel", "CyberPanel Login",
                    " LiteSpeed "],
        "default_creds": [("admin", "cyberpanel"), ("admin", "1234567")],
    },
    # aaPanel
    {
        "type": "aapanel",
        "paths": ["/aapanel/", "/aapanel", "/panel/", "/:8888/"],
        "keywords": ["aaPanel", "aapanel", "宝塔面板", "Bt.cn"],
        "port_hints": [8888],
        "default_creds": [("admin", "aapanel")],
    },
    # Webmin / Virtualmin
    {
        "type": "webmin",
        "paths": ["/webmin/", "/webmin", "/:10000/"],
        "keywords": ["Webmin", "webmin", "Webmin Login",
                    "Virtualmin", "virtualmin"],
        "port_hints": [10000],
        "default_creds": [("admin", "webmin"), ("root", "webmin")],
    },
    # Cloudmin
    {
        "type": "cloudmin",
        "paths": ["/cloudmin/", "/cloudmin"],
        "keywords": ["Cloudmin", "cloudmin"],
        "default_creds": [("admin", "cloudmin")],
    },
    # ZPanel / Sentora
    {
        "type": "zpanel",
        "paths": ["/zpanel/", "/sentora/", "/panel/"],
        "keywords": ["ZPanel", "zpanel", "Sentora", "sentora"],
        "default_creds": [("admin", "zpanel"), ("admin", "sentora")],
    },
    # SPanel
    {
        "type": "spanel",
        "paths": ["/spanel/", "/spanel"],
        "keywords": ["SPanel", "spanel", "SPanel Login"],
        "default_creds": [("admin", "spanel")],
    },
    # Blesta (billing)
    {
        "type": "blesta",
        "paths": ["/admin/", "/billing/admin/"],
        "keywords": ["Blesta", "blesta", "Blesta Admin"],
        "default_creds": [("admin", "blesta")],
    },
    # WHMCS (billing)
    {
        "type": "whmcs",
        "paths": ["/whmcs/admin/", "/whmcs/", "/billing/admin/"],
        "keywords": ["WHMCS", "whmcs", "WHMCompleteSolution"],
        "default_creds": [("admin", "whmcs")],
    },
    # phpMyAdmin (虽然不是面板, 但常被一起管理)
    {
        "type": "phpmyadmin",
        "paths": ["/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/mysql/"],
        "keywords": ["phpMyAdmin", "phpMyAdmin", "pma_",
                    "input_username", "pma_password"],
        "default_creds": [],
    },
    # 通用登录后台
    {
        "type": "generic_admin",
        "paths": ["/admin/", "/admin", "/manager/", "/manage/",
                 "/backend/", "/dashboard/", "/administrator/"],
        "keywords": ["admin", "login", "sign in", "dashboard",
                    "管理后台", "admin panel"],
        "default_creds": [],
    },
]


class HostingPanelDetect:
    """
    主机面板检测器.

    用法:
        async with HostingPanelDetect() as detect:
            results = await detect.detect("https://blastzonewebhosting.com")

        # 同步模式:
        detect = HostingPanelDetect()
        results = detect.detect_sync("https://blastzonewebhosting.com")
    """

    def __init__(self, session=None, timeout: float = 8.0, concurrency: int = 10):
        """
        Args:
            session: 可选的 requests.Session (已配代理)
            timeout: 单请求超时
            concurrency: 并发探测数
        """
        self.session = session
        self.timeout = timeout
        self.concurrency = concurrency

    # ============================================================
    # 核心: 路径探测
    # ============================================================

    def _check_path_sync(self, base_url: str, path: str,
                         keywords: List[str]) -> Optional[PanelInfo]:
        """同步探测单个路径 (使用 requests 库)."""
        import requests as req_lib

        if path.startswith(":"):
            # 端口专用路径: :8443/ 表示在 8443 端口上探测
            port = int(path.split(":")[1].split("/")[0])
            parsed = urlparse(base_url)
            probe_url = f"{parsed.scheme}://{parsed.hostname}:{port}/"
        else:
            probe_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

        session = self.session or req_lib.Session()
        try:
            resp = session.get(
                probe_url, timeout=self.timeout,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            )
            body = resp.text
            status = resp.status_code
            server = resp.headers.get("Server", "")
            content_type = resp.headers.get("Content-Type", "")

            # 成功: 2xx/3xx 且有关键词
            if status < 400:
                for kw in keywords:
                    if re.search(kw, body, re.I) or re.search(kw, str(resp.headers), re.I):
                        # 提取版本
                        version = self._extract_version(body, kw)
                        # 计算置信度
                        confidence = self._calc_confidence(keywords, body, kw)
                        # 检测到的面板类型
                        # 从 PANEL_FINGERPRINTS 找对应类型
                        panel_type = "unknown"
                        default_creds = []
                        for fp in PANEL_FINGERPRINTS:
                            if kw in fp.get("keywords", []):
                                panel_type = fp["type"]
                                default_creds = fp.get("default_creds", [])
                                break
                        if not panel_type or panel_type == "unknown":
                            panel_type = kw.lower().replace(" ", "_")[:20]

                        return PanelInfo(
                            panel_type=panel_type,
                            version=version or "",
                            login_url=probe_url,
                            server_software=server,
                            detect_method="path+keyword",
                            confidence=confidence,
                            default_creds=default_creds,
                        )

            # 也检查 403 但有面板关键词 (被保护的页面)
            if status == 403:
                for kw in keywords:
                    if re.search(kw, body, re.I):
                        return PanelInfo(
                            panel_type=kw.lower()[:20],
                            login_url=probe_url,
                            server_software=server,
                            detect_method="403+keyword",
                            confidence=0.5,
                        )
        except Exception:
            pass
        return None

    @staticmethod
    def _extract_version(body: str, keyword: str) -> str:
        """从响应体中提取面板版本号."""
        # 通用版本号模式
        version_patterns = [
            r'ver[sion]*[:\s]*([\d.]+)',
            r'v([\d]+\.[\d]+(?:\.[\d]+)?)',
            r'version["\']?\s*[:=]\s*["\']?([\d.]+)',
            r'([\d]+\.[\d]+\.[\d]+)',
        ]
        for pat in version_patterns:
            m = re.search(pat, body[:5000], re.I)
            if m:
                ver = m.group(1)
                # 过滤明显不是版本号的数字
                if len(ver) >= 3 and ver[0].isdigit():
                    return ver
        return ""

    @staticmethod
    def _calc_confidence(keywords: List[str], body: str,
                         matched_keyword: str) -> float:
        """计算检测置信度 (0.0~1.0)."""
        matched = matched_keyword.lower()
        body_lower = body.lower()

        score = 0.5  # 基础: 有一个关键词匹配
        # 多个额外关键词匹配加分
        extra_matches = sum(1 for kw in keywords
                          if kw.lower() != matched and kw.lower() in body_lower)
        score += extra_matches * 0.15

        return min(score, 1.0)

    # ============================================================
    # 同步入口
    # ============================================================

    def detect_sync(self, base_url: str) -> PanelDetectResult:
        """
        同步检测主机面板 (单域名).

        Args:
            base_url: 目标基本 URL (如 "https://blastzonewebhosting.com")

        Returns:
            PanelDetectResult
        """
        import requests as req_lib

        result = PanelDetectResult(base_url=base_url)
        start = time.time()

        session = self.session or req_lib.Session()
        checked = 0
        found_panels = []

        for fp in PANEL_FINGERPRINTS:
            keywords = fp["keywords"]
            for path in fp["paths"]:
                checked += 1
                info = self._check_path_sync(base_url, path, keywords)
                if info:
                    # 如果路径含通配符, 更新面板类型
                    if not info.panel_type or info.panel_type == "unknown":
                        info.panel_type = fp["type"]
                    if not info.default_creds:
                        info.default_creds = fp.get("default_creds", [])
                    found_panels.append(info)
                    break  # 同一面板的其它路径不用再试

            # 端口探测 (如果有 port_hints)
            for port in fp.get("port_hints", []):
                checked += 1
                port_path = f":{port}/"
                info = self._check_path_sync(base_url, port_path, keywords)
                if info:
                    if not info.panel_type or info.panel_type == "unknown":
                        info.panel_type = fp["type"]
                    found_panels.append(info)

        result.panels = found_panels
        result.total_checked = checked
        result.total_time_sec = round(time.time() - start, 1)
        return result

    # ============================================================
    # 默认凭据试探
    # ============================================================

    def check_default_creds(self, panel: PanelInfo,
                            usernames: Optional[List[str]] = None,
                            passwords: Optional[List[str]] = None) -> List[str]:
        """
        对检测到的面板尝试默认凭据.

        Args:
            panel: 之前检测到的面板信息
            usernames: 可选, 覆盖默认用户名列表
            passwords: 可选, 覆盖默认密码列表

        Returns:
            成功尝试的描述列表
        """
        import requests as req_lib

        if not panel.default_creds and not (usernames and passwords):
            return []

        session = self.session or req_lib.Session()
        url = panel.login_url

        creds_to_try = panel.default_creds
        if usernames and passwords:
            creds_to_try = [(u, p) for u in usernames for p in passwords[:5]]

        results = []
        for username, password in creds_to_try[:10]:  # 最多试 10 组
            try:
                resp = session.post(
                    url,
                    data={panel.panel_type + "_user": username,
                          panel.panel_type + "_pass": password},
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                if resp.status_code in (301, 302, 303):
                    redirect = resp.headers.get("Location", "")
                    if "login" not in redirect.lower():
                        results.append(f"{username}:{password} -> {redirect}")
            except Exception:
                pass

        return results


# ============================================================
# 异步接口
# ============================================================

class AsyncHostingPanelDetect(HostingPanelDetect):
    """异步版本: 使用 asyncio 并发探测."""

    async def detect(self, base_url: str) -> PanelDetectResult:
        """异步检测主机面板."""
        import requests as req_lib

        result = PanelDetectResult(base_url=base_url)
        start = time.time()

        session = self.session or req_lib.Session()

        async def check_one(fp, path) -> Optional[PanelInfo]:
            return await asyncio.to_thread(
                self._check_path_sync, base_url, path, fp["keywords"]
            )

        sem = asyncio.Semaphore(self.concurrency)
        tasks = []

        async def bounded_check(fp, path):
            async with sem:
                info = await check_one(fp, path)
                if info:
                    info.panel_type = fp["type"]
                    info.default_creds = fp.get("default_creds", [])
                return info

        for fp in PANEL_FINGERPRINTS:
            for path in fp["paths"]:
                tasks.append(bounded_check(fp, path))
            for port in fp.get("port_hints", []):
                port_path = f":{port}/"
                tasks.append(bounded_check(fp, port_path))

        results = await asyncio.gather(*tasks)
        found = [r for r in results if r is not None]

        result.panels = found
        result.total_checked = len(tasks)
        result.total_time_sec = round(time.time() - start, 1)
        return result


# ============================================================
# 快捷函数
# ============================================================

def detect_panels(base_url: str, session=None) -> PanelDetectResult:
    """快捷同步检测."""
    detect = HostingPanelDetect(session=session)
    return detect.detect_sync(base_url)


async def async_detect_panels(base_url: str, session=None) -> PanelDetectResult:
    """快捷异步检测."""
    detect = AsyncHostingPanelDetect(session=session)
    return await detect.detect(base_url)