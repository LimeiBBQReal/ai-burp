"""
V4 深度采集器 - 把 V4 扫描结果喂给 V3 发现模块.

核心循环:
    1. V4 scan_hosts 发现开放端口 (L1-L2)
    2. 对每个 HTTP 服务, 桥接 V3 DirFuzzer 做目录爆破 (L3)
    3. 发现的新端点加入 AssetGraph (L4 流量点清单)
    4. 对每个非 HTTP 服务, 用 V4 原生深度检测

设计:
    - 不重写 V3 模块, 用 bridge.create_bridge_burp 共享连接池
    - 采集是迭代的: 每发现新端点, 可以触发新一轮采集
    - 结果统一写入 AssetGraph, 供 AI 决策层消费
"""

import asyncio
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field

from .engine import TrafficEngine
from .bridge import create_bridge_burp
from .scan_result import ScanResult, AssetEntry


@dataclass
class CollectedAsset:
    """深度采集发现的资产 (比 AssetEntry 更丰富)"""
    target: str               # host:port 或 URL
    source: str               # 发现方式: port-scan / dir-fuzz / param-discover / protocol-deep
    asset_type: str           # endpoint / form-param / js-endpoint / share / file / service
    value: str                # 具体值 (URL / 参数名 / 共享名 / 文件路径)
    details: Dict[str, Any] = field(default_factory=dict)  # 额外信息 (状态码/标题/参数列表...)
    tags: List[str] = field(default_factory=list)


@dataclass
class DeepCollectResult:
    """深度采集结果"""
    scan_result: ScanResult           # V4 初始扫描结果
    discovered: List[CollectedAsset] = field(default_factory=list)  # 深度发现的资产
    stats: Dict[str, int] = field(default_factory=dict)  # 统计

    def to_dict(self) -> Dict[str, Any]:
        import json
        return {
            "scan_summary": self.scan_result.summary(),
            "discovered": [
                {
                    "target": a.target, "source": a.source,
                    "type": a.asset_type, "value": a.value,
                    "tags": a.tags, **a.details,
                }
                for a in self.discovered
            ],
            "stats": self.stats,
        }

    def to_json(self) -> str:
        import json
        return json.dumps(self.to_dict(), ensure_ascii=False, default=str)


class DeepCollector:
    """
    V4 深度采集器 - 桥接 V3 发现能力到 V4.

    用法:
        async with TrafficEngine() as engine:
            collector = DeepCollector(engine)
            # 先扫描
            scan = await engine.scan_hosts(["127.0.0.1"], ports=[80, 6379])
            # 再深度采集
            result = await collector.deep_collect(scan)
            print(result.to_json())
    """

    def __init__(self, engine: TrafficEngine):
        self.engine = engine
        self._burp: Optional[Any] = None  # V3 兼容的 SyncBurp (延迟创建)
        self._history: Optional[Any] = None  # V3 History (V3/V4 共享)
        self._async_burp: Optional[Any] = None  # V4 AsyncBurp (VulnScanner 用)

    def _get_burp(self):
        """获取 V3 兼容的 SyncBurp (延迟创建, 必须在 to_thread 内调用)"""
        if self._burp is None:
            self._burp = create_bridge_burp(self.engine, delay=0.0)
        return self._burp

    def _make_fuzzer(self, wordlist_name):
        """在 to_thread 里创建 DirFuzzer (确保 SyncBurp 在子线程创建)"""
        from ..plugins.discovery import DirFuzzer
        # 每次在子线程创建新的 SyncBurp (避免跨 loop)
        burp = create_bridge_burp(self.engine, delay=0.0)
        return DirFuzzer(burp, threads=5)

    def _get_async_burp(self):
        """获取 V4 的 AsyncBurp (VulnScanner/detectors 用)"""
        if self._async_burp is None:
            http_adapter = self.engine.adapter("http")
            self._async_burp = http_adapter._burp
        return self._async_burp

    def _get_history(self):
        """获取/创建 V3 History (AssetGraph/TrafficDiff 用)"""
        if self._history is None:
            from ..core.history import History
            self._history = History()
        return self._history

    # ============================================================
    # 批 1: 侦察类模块桥接
    # ============================================================

    async def collect_fingerprint(self, url: str) -> List[CollectedAsset]:
        """指纹识别 (V3 fingerprint.py) - 技术栈/CMS 检测"""
        from aiburp.traffic.bridge import create_bridge_burp

        def _run():
            from ..fingerprint.detector import TechDetector
            burp = create_bridge_burp(self.engine, delay=0.0)
            r = burp.get(url)
            detector = TechDetector()
            # TechDetector 需要一个有 .headers/.body 的对象
            class _MockResp:
                def __init__(self, r):
                    self.headers = r.headers
                    self.body = r.body
                    self.text = r.body
            return detector.detect(response=_MockResp(r))

        try:
            techs = await asyncio.to_thread(_run)
        except Exception:
            return []

        assets = []
        for tech in (techs if isinstance(tech, list) else [techs]):
            if tech and isinstance(tech, dict):
                assets.append(CollectedAsset(
                    target=url, source="fingerprint",
                    asset_type="tech-stack",
                    value=str(tech.get("name", tech)),
                    details=tech if isinstance(tech, dict) else {},
                ))
        return assets

    async def collect_waf_detect(self, url: str) -> Optional[CollectedAsset]:
        """WAF 检测 (V3 waf_detect.py)"""
        def _run():
            from ..plugins.recon.waf_detect import WAFDetector
            detector = WAFDetector(timeout=5)
            return detector.detect(url)

        try:
            result = await asyncio.to_thread(_run)
            return CollectedAsset(
                target=url, source="waf-detect",
                asset_type="waf",
                value=result.waf_name if hasattr(result, "waf_name") else str(result),
                details={"blocked": getattr(result, "blocked", False)},
                tags=["WAF-BLOCKED"] if getattr(result, "blocked", False) else [],
            )
        except Exception:
            return None

    async def collect_api_discover(self, url: str) -> List[CollectedAsset]:
        """API 发现 (V3 api_discover.py) - Swagger/GraphQL"""
        def _run():
            from ..plugins.recon.api_discover import APIDiscoverPlugin
            plugin = APIDiscoverPlugin()
            return plugin.discover(url, timeout=5)

        try:
            result = await asyncio.to_thread(_run)
        except Exception:
            return []

        assets = []
        if isinstance(result, dict):
            for endpoint in result.get("endpoints", []):
                assets.append(CollectedAsset(
                    target=url, source="api-discover",
                    asset_type="api-endpoint",
                    value=str(endpoint.get("path", endpoint)),
                    details=endpoint if isinstance(endpoint, dict) else {},
                ))
        return assets

    async def collect_asset_graph(self) -> Any:
        """资产图谱 (V3 asset_graph.py) - 从 History 构建资产关联"""
        def _run():
            from ..core.asset_graph import AssetGraph
            history = self._get_history()
            graph = AssetGraph(history)
            graph.build()
            return graph

        try:
            return await asyncio.to_thread(_run)
        except Exception:
            return None

    async def collect_traffic_diff(self, url: str) -> List[CollectedAsset]:
        """流量差异分析 (V3 traffic_diff.py) - 隐藏参数发现"""
        def _run():
            from ..core.traffic_diff import TrafficDiff
            td = TrafficDiff(history=self._get_history())
            anomalies = td.find_anomalies(url)
            hidden = td.discover_hidden_params(url)
            return anomalies, hidden

        try:
            anomalies, hidden = await asyncio.to_thread(_run)
        except Exception:
            return []

        assets = []
        for param, info in (hidden.items() if isinstance(hidden, dict) else []):
            assets.append(CollectedAsset(
                target=url, source="traffic-diff",
                asset_type="hidden-param",
                value=param,
                details=info if isinstance(info, dict) else {"info": str(info)},
                tags=["HIDDEN-PARAM"],
            ))
        return assets

    # ============================================================
    # 批 2: 漏洞利用类模块桥接
    # ============================================================

    async def collect_extractor(self, url: str, param: str, value: str,
                                 db_type: str = "auto") -> List[CollectedAsset]:
        """UNION 注入数据提取 (V3 extractor.py)"""
        def _run():
            from ..plugins.extractor import UnionExtractor
            burp = create_bridge_burp(self.engine, delay=0.0)
            extractor = UnionExtractor(burp)
            return extractor.extract(url, param, value, db=db_type)

        try:
            data = await asyncio.to_thread(_run)
        except Exception:
            return []

        assets = []
        if isinstance(data, dict):
            for table, rows in data.items():
                assets.append(CollectedAsset(
                    target=url, source="extractor",
                    asset_type="extracted-data",
                    value=f"table:{table} ({len(rows) if isinstance(rows, list) else '?'} rows)",
                    tags=["DATA-EXTRACTED"],
                ))
        return assets

    async def collect_smart_payload(self, url: str) -> Optional[CollectedAsset]:
        """智能 Payload 生成 (V3 smart_payload.py) - WAF 绕过"""
        def _run():
            from ..plugins.smart_payload import SmartPayloadGenerator
            burp = create_bridge_burp(self.engine, delay=0.0)
            gen = SmartPayloadGenerator(burp)
            waf_result = gen.detect_waf(url)
            if waf_result.detected:
                bypass = gen.generate_bypass_payloads(url, waf_result.waf_name)
                return waf_result, bypass
            return waf_result, None

        try:
            waf, bypass = await asyncio.to_thread(_run)
            asset = CollectedAsset(
                target=url, source="smart-payload",
                asset_type="waf-bypass",
                value=f"WAF: {getattr(waf, 'waf_name', 'none')}",
                details={
                    "waf_detected": getattr(waf, "detected", False),
                    "bypass_count": len(bypass) if bypass else 0,
                },
            )
            if getattr(waf, "detected", False):
                asset.tags.append("WAF-DETECTED")
            return asset
        except Exception:
            return None

    # ============================================================
    # 批 3: 报告管理类模块桥接
    # ============================================================

    def generate_report(self, result: DeepCollectResult, fmt: str = "text") -> str:
        """
        生成报告 (V3 report_generator.py).

        Args:
            result: DeepCollectResult
            fmt: "text" / "md" / "html"
        """
        if fmt == "text":
            return self.report_text(result)
        elif fmt in ("md", "html"):
            # 桥接 V3 ReportGenerator
            try:
                from ..plugins.report_generator import ReportGenerator
                gen = ReportGenerator(project="deep_collect")
                # 把发现的漏洞写入 generator
                for a in result.discovered:
                    if a.source == "vuln-scan":
                        gen.add_finding(
                            title=a.value,
                            severity="high" if "HIGH" in a.tags else "medium",
                            description=a.details.get("evidence", ""),
                        )
                if fmt == "md":
                    return gen.generate_md("report.md")
                else:
                    return gen.generate_html("report.html")
            except Exception:
                return self.report_text(result)
        return self.report_text(result)

    async def deep_collect(
        self,
        scan_result: ScanResult,
        dir_wordlist: str = "quick",
        dir_bypass: bool = True,
        do_param_discover: bool = False,
        do_vuln_scan: bool = False,
        vuln_types: List[str] = None,
    ) -> DeepCollectResult:
        """
        对扫描结果做深度采集.

        Args:
            scan_result:      V4 scan_hosts/scan_cidr 的结果
            dir_wordlist:     目录爆破字典名 (quick/common/asp/sensitive)
            dir_bypass:       是否对 401/403 做绕过尝试
            do_param_discover: 是否做参数发现 (较慢, 默认 False)
            do_vuln_scan:     是否做漏洞扫描 (默认 False, 较慢)
            vuln_types:       漏洞类型列表 (None = 全部: sqli/xss/ssrf/cmdi/lfi/ssti)

        Returns:
            DeepCollectResult, 含原始扫描 + 深度发现
        """
        result = DeepCollectResult(scan_result=scan_result)
        result.stats = {
            "open_ports": scan_result.open_count,
            "http_services": 0,
            "dirs_found": 0,
            "params_found": 0,
            "vulns_found": 0,
            "fingerprints": 0,
            "waf_detected": 0,
            "api_endpoints": 0,
            "deep_checks": 0,
        }

        for entry in scan_result.open_entries():
            target_url = self._entry_to_url(entry)

            # === HTTP 服务: 目录爆破 ===
            if entry.protocol in ("http", "https") or entry.port in (80, 443, 8080, 8443, 8000, 8888):
                result.stats["http_services"] += 1
                await self._collect_http(entry, target_url, dir_wordlist, dir_bypass, result)

                # 指纹识别 (技术栈/CMS)
                fp_assets = await self.collect_fingerprint(target_url)
                for a in fp_assets:
                    result.discovered.append(a)

                # WAF 检测
                waf_asset = await self.collect_waf_detect(target_url)
                if waf_asset:
                    result.discovered.append(waf_asset)

                # API 发现 (Swagger/GraphQL)
                api_assets = await self.collect_api_discover(target_url)
                for a in api_assets:
                    result.discovered.append(a)

                # 可选: 参数发现 (JS/表单/链接)
                if do_param_discover:
                    await self._collect_params(entry, target_url, result)
                    # 流量差异 (隐藏参数)
                    diff_assets = await self.collect_traffic_diff(target_url)
                    for a in diff_assets:
                        result.discovered.append(a)

                # 可选: 漏洞扫描 (SQLi/XSS/SSRF/CMDi/LFI/SSTI)
                if do_vuln_scan:
                    await self._collect_vulns(entry, target_url, result, vuln_types)

            # === Redis: 未授权检测 ===
            elif entry.protocol == "redis":
                await self._collect_redis(entry, result)

            # === MySQL: 弱口令 ===
            elif entry.protocol == "mysql":
                await self._collect_mysql(entry, result)

            # === SMB: 空会话 ===
            elif entry.protocol == "smb":
                await self._collect_smb(entry, result)

            # === RMI: 反序列化风险 ===
            elif entry.protocol == "rmi":
                await self._collect_rmi(entry, result)

        return result

    def _entry_to_url(self, entry: AssetEntry) -> str:
        """AssetEntry → URL"""
        if entry.port in (443, 8443):
            return f"https://{entry.host}:{entry.port}/"
        return f"http://{entry.host}:{entry.port}/"

    # ============================================================
    # HTTP 深度采集 (桥接 V3 DirFuzzer)
    # ============================================================

    async def _collect_http(
        self, entry: AssetEntry, url: str,
        wordlist: str, bypass: bool, result: DeepCollectResult,
    ):
        """HTTP 深度采集: 目录爆破 + (可选)参数发现"""
        # 在 to_thread 内部创建 SyncBurp + DirFuzzer (避免跨 loop 协程泄漏)
        engine = self.engine

        def _run_fuzz():
            from ..plugins.discovery import DirFuzzer
            burp = create_bridge_burp(engine, delay=0.0)
            fuzzer = DirFuzzer(burp, threads=5)
            return fuzzer.fuzz(url, wordlist=wordlist, bypass=bypass)

        try:
            report = await asyncio.to_thread(_run_fuzz)
        except Exception as e:
            result.discovered.append(CollectedAsset(
                target=url, source="dir-fuzz",
                asset_type="error", value=str(e)[:100],
            ))
            return

        # 把发现加入结果 (DirFuzzReport.results 是全部结果)
        all_found = report.results or []
        for found in all_found:
            asset = CollectedAsset(
                target=url, source="dir-fuzz",
                asset_type="endpoint",
                value=found.url,
                details={
                    "status": found.status,
                    "length": found.length,
                    "title": found.title,
                    "reason": found.reason,
                    "interesting": found.interesting,
                },
            )
            if found.interesting:
                asset.tags.append("INTERESTING")
            if "⚠" in (found.reason or ""):
                asset.tags.append("SENSITIVE")
            result.discovered.append(asset)
            result.stats["dirs_found"] += 1

        result.stats["deep_checks"] += 1

    # ============================================================
    # HTTP 参数发现 (桥接 V3 ParamDiscoverer)
    # ============================================================

    async def _collect_params(
        self, entry: AssetEntry, url: str, result: DeepCollectResult,
    ):
        """参数发现: 表单/链接/JS 分析 (桥接 V3 ParamDiscoverer)"""
        def _run_discover():
            from ..plugins.param_discover import ParamDiscoverer
            discoverer = ParamDiscoverer(timeout=5)
            return discoverer.discover(url, depth=1, analyze_js=True)

        try:
            disc = await asyncio.to_thread(_run_discover)
        except Exception:
            return

        # 表单参数
        for form in (disc.forms or []):
            for param in form.get("params", []):
                result.discovered.append(CollectedAsset(
                    target=url, source="param-discover",
                    asset_type="form-param",
                    value=f"{form.get('method','GET')} {form.get('action','')} ?{param}",
                    details={"form": form.get("action", "")},
                ))
                result.stats["params_found"] += 1

        # JS 里发现的端点
        for ep in (disc.endpoints or []):
            result.discovered.append(CollectedAsset(
                target=url, source="param-discover",
                asset_type="js-endpoint",
                value=ep.url,
                details={"method": ep.method},
            ))
            result.stats["params_found"] += 1

        # JS 里的密钥
        for secret in (getattr(disc, 'js_secrets', None) or []):
            result.discovered.append(CollectedAsset(
                target=url, source="param-discover",
                asset_type="js-secret",
                value=f"{secret.type}: {secret.value[:50]}",
                tags=["SENSITIVE"],
            ))

    # ============================================================
    # HTTP 漏洞扫描 (桥接 V3 VulnScanner, 用 V4 AsyncBurp)
    # ============================================================

    async def _collect_vulns(
        self, entry: AssetEntry, url: str, result: DeepCollectResult,
        vuln_types: Optional[List[str]] = None,
    ):
        """漏洞扫描: SQLi/XSS/SSRF/CMDi/LFI/SSTI (桥接 V3 VulnScanner)"""
        from ..burp import AsyncBurp

        # 用 V4 的 AsyncBurp (async 接口, 与 VulnScanner 兼容)
        http_adapter = self.engine.adapter("http")
        async_burp = http_adapter._burp

        from ..detectors import AsyncVulnScanner
        scanner = AsyncVulnScanner(async_burp)

        # 先发现参数 (用目录爆破发现的端点)
        endpoints_to_test = [url]
        for a in result.discovered:
            if a.source == "dir-fuzz" and a.details.get("status") in (200, 301, 302):
                endpoints_to_test.append(a.value)

        for ep_url in endpoints_to_test[:10]:  # 最多扫 10 个端点
            # 从 URL 提取参数 (默认用 id/q 参数测试)
            parsed = ep_url.split("?")
            base_url = parsed[0]
            params = parsed[1] if len(parsed) > 1 else "id"

            for param in params.split("&")[:3]:  # 每个端点最多 3 个参数
                param_name = param.split("=")[0] if "=" in param else param
                try:
                    findings = await scanner.scan(
                        base_url, param_name, "1", types=vuln_types
                    )
                    for f in findings:
                        result.discovered.append(CollectedAsset(
                            target=base_url, source="vuln-scan",
                            asset_type="vulnerability",
                            value=f"{f.vuln_type} ({f.confidence})",
                            details={
                                "evidence": f.evidence[:100],
                                "payload": f.payload[:50],
                                "param": param_name,
                            },
                            tags=[f"VULN-{f.vuln_type.upper()}", f"CONF-{f.confidence.upper()}"],
                        ))
                        result.stats["vulns_found"] += 1
                except Exception:
                    pass

        result.stats["deep_checks"] += 1

    # ============================================================
    # 协议深度采集 (V4 原生)
    # ============================================================

    async def _collect_redis(self, entry: AssetEntry, result: DeepCollectResult):
        """Redis 未授权深度检测"""
        try:
            resp = await self.engine.check_unauth(entry.target, protocol="redis", timeout=5)
            if resp.ok:
                result.discovered.append(CollectedAsset(
                    target=entry.target, source="protocol-deep",
                    asset_type="service",
                    value=f"redis-unauth: {resp.banner}",
                    details={
                        "tags": resp.tags,
                        "anomalies": resp.anomalies,
                        "text": resp.text[:200],
                    },
                    tags=resp.tags,
                ))
                result.stats["deep_checks"] += 1
        except Exception:
            pass

    async def _collect_mysql(self, entry: AssetEntry, result: DeepCollectResult):
        """MySQL 弱口令检测"""
        try:
            resp = await self.engine.check_unauth(entry.target, protocol="mysql", timeout=5)
            if resp.ok:
                result.discovered.append(CollectedAsset(
                    target=entry.target, source="protocol-deep",
                    asset_type="service",
                    value=f"mysql: {resp.banner}",
                    details={"tags": resp.tags, "anomalies": resp.anomalies},
                    tags=resp.tags,
                ))
                result.stats["deep_checks"] += 1
        except Exception:
            pass

    async def _collect_smb(self, entry: AssetEntry, result: DeepCollectResult):
        """SMB 空会话枚举"""
        try:
            resp = await self.engine.adapter("smb").check_null_session(
                entry.target, timeout=5
            )
            if resp.ok:
                result.discovered.append(CollectedAsset(
                    target=entry.target, source="protocol-deep",
                    asset_type="share",
                    value=f"smb: {resp.banner}",
                    details={
                        "tags": resp.tags,
                        "text": resp.text[:200],
                    },
                    tags=resp.tags,
                ))
                result.stats["deep_checks"] += 1
        except Exception:
            pass

    async def _collect_rmi(self, entry: AssetEntry, result: DeepCollectResult):
        """RMI 反序列化风险检测"""
        try:
            resp = await self.engine.adapter("rmi").check_deserial(
                entry.target, timeout=5
            )
            if resp.ok and "RMI" in resp.tags:
                result.discovered.append(CollectedAsset(
                    target=entry.target, source="protocol-deep",
                    asset_type="service",
                    value=f"rmi: {resp.banner}",
                    details={"tags": resp.tags},
                    tags=resp.tags,
                ))
                result.stats["deep_checks"] += 1
        except Exception:
            pass

    # ============================================================
    # 报告
    # ============================================================

    def report_text(self, result: DeepCollectResult) -> str:
        """人类可读的深度采集报告"""
        lines = []
        lines.append("=" * 70)
        lines.append("V4 深度采集报告 (DeepCollect)")
        lines.append("=" * 70)

        s = result.stats
        lines.append(f"开放端口: {s.get('open_ports', 0)} | "
                      f"HTTP: {s.get('http_services', 0)} | "
                      f"目录: {s.get('dirs_found', 0)} | "
                      f"参数: {s.get('params_found', 0)} | "
                      f"漏洞: {s.get('vulns_found', 0)} | "
                      f"指纹: {s.get('fingerprints', 0)} | "
                      f"WAF: {s.get('waf_detected', 0)} | "
                      f"API: {s.get('api_endpoints', 0)}")
        lines.append("-" * 70)

        # 按来源分组
        by_source: Dict[str, List[CollectedAsset]] = {}
        for a in result.discovered:
            by_source.setdefault(a.source, []).append(a)

        for source, assets in by_source.items():
            source_label = {
                "dir-fuzz": "📂 目录爆破发现",
                "protocol-deep": "🔌 协议深度检测",
                "param-discover": "📝 参数/JS 发现",
                "vuln-scan": "💉 漏洞扫描发现",
                "fingerprint": "🔍 指纹识别",
                "waf-detect": "🛡️ WAF 检测",
                "api-discover": "🌐 API 发现",
                "traffic-diff": "📊 流量差异",
                "extractor": "📤 数据提取",
                "smart-payload": "🧠 智能 Payload",
            }.get(source, source)
            lines.append(f"\n{source_label} ({len(assets)}):")
            for a in assets[:30]:  # 最多显示 30 条
                tags_str = f" [{','.join(a.tags[:3])}]" if a.tags else ""
                detail_str = ""
                if a.details.get("status"):
                    detail_str = f" {a.details['status']} {a.details.get('title','')[:20]}"
                lines.append(f"  {a.value[:70]}{detail_str}{tags_str}")
            if len(assets) > 30:
                lines.append(f"  ...还有 {len(assets)-30} 条")

        return "\n".join(lines)
